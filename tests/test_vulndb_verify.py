"""Runtime opt-in signature verification of the --vuln-db feed (aws_live_scanner
._do_load_vuln_db). Back-compat: unsigned feeds still load when no --vuln-db-pubkey is set.
Fail-closed: with a pubkey configured, an unsigned/bad/tampered feed is REJECTED (WARN, no
feed). Offline; a tiny signed bundle built with the vendored Ed25519."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_ed25519
from test_live_scanner import make_scanner

FEED = {"records": [{"id": "CVE-1", "affected": [{"package": {"ecosystem": "Debian:12",
        "name": "openssl"}, "ranges": [{"type": "ECOSYSTEM",
        "events": [{"introduced": "0"}, {"fixed": "9.9"}]}]}]}],
        "epss": {"CVE-1": 0.9}, "kev": ["CVE-1"], "exploits": []}


def _write_feed(path, feed=FEED):
    data = json.dumps(feed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    with open(path, "wb") as fh:
        fh.write(data)
    return data


def _scanner(tmp_path, pubkey=None):
    s = make_scanner(sections=["VULN"])
    s.vuln_db_path = str(tmp_path / "feed.json")
    s.vuln_db_pubkey = pubkey
    return s


def _warns(s):
    return [r for r in s.results if getattr(r, "check_id", "") == "CWPP-04"
            and getattr(r, "status", "") == "WARN"]


def test_unsigned_feed_loads_when_no_pubkey(tmp_path):
    _write_feed(tmp_path / "feed.json")
    s = _scanner(tmp_path, pubkey=None)
    bundle = s._load_vuln_db()
    assert bundle is not None and "CVE-1" in bundle[2]     # kev set carried through
    assert _warns(s) == []


def test_signed_feed_verifies_and_loads(tmp_path):
    data = _write_feed(tmp_path / "feed.json")
    seed = bytes.fromhex("11" * 32)
    pub = aws_ed25519.publickey(seed)
    (tmp_path / "feed.json.sig").write_text(aws_ed25519.sign(seed, data).hex())
    s = _scanner(tmp_path, pubkey=pub.hex())
    bundle = s._load_vuln_db()
    assert bundle is not None
    assert _warns(s) == []                                 # verified silently


def test_pubkey_set_but_feed_unsigned_is_rejected(tmp_path):
    _write_feed(tmp_path / "feed.json")                    # no .sig written
    pub = aws_ed25519.publickey(bytes.fromhex("22" * 32))
    s = _scanner(tmp_path, pubkey=pub.hex())
    assert s._load_vuln_db() is None                       # fail-closed
    assert len(_warns(s)) == 1 and "verification FAILED" in _warns(s)[0].message


def test_tampered_feed_rejected(tmp_path):
    data = _write_feed(tmp_path / "feed.json")
    seed = bytes.fromhex("33" * 32)
    (tmp_path / "feed.json.sig").write_text(aws_ed25519.sign(seed, data).hex())
    # tamper AFTER signing — the signature no longer matches the bytes
    _write_feed(tmp_path / "feed.json", {**FEED, "kev": ["CVE-INJECTED"]})
    s = _scanner(tmp_path, pubkey=aws_ed25519.publickey(seed).hex())
    assert s._load_vuln_db() is None
    assert len(_warns(s)) == 1


def test_malformed_pubkey_fails_closed_not_open(tmp_path):
    # the operator opted INTO enforcement, but the key is a 63-char truncated hex (unresolvable).
    # It must REJECT (fail-closed) — never silently load the feed unsigned (trust-anything).
    data = _write_feed(tmp_path / "feed.json")
    (tmp_path / "feed.json.sig").write_text(aws_ed25519.sign(bytes.fromhex("55" * 32), data).hex())
    s = _scanner(tmp_path, pubkey="ab" * 31 + "c")           # 63 hex chars — resolves to None
    assert s._load_vuln_db() is None
    assert len(_warns(s)) == 1 and "could not be resolved" in _warns(s)[0].message


def test_unresolvable_pubkey_path_fails_closed(tmp_path):
    _write_feed(tmp_path / "feed.json")
    s = _scanner(tmp_path, pubkey=str(tmp_path / "does-not-exist.pub"))
    assert s._load_vuln_db() is None                          # fail-closed, not fall-through
    assert len(_warns(s)) == 1


def test_pubkey_from_pub_file_path(tmp_path):
    data = _write_feed(tmp_path / "feed.json")
    seed = bytes.fromhex("44" * 32)
    pub = aws_ed25519.publickey(seed)
    (tmp_path / "feed.json.sig").write_text(aws_ed25519.sign(seed, data).hex())
    (tmp_path / "key.pub").write_text(pub.hex() + "\n")
    s = _scanner(tmp_path, pubkey=str(tmp_path / "key.pub"))
    assert s._load_vuln_db() is not None
