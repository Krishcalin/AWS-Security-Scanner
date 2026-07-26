#!/usr/bin/env python3
"""overwatch-vulndb — assemble + sign an OFFLINE vulnerability feed bundle for the
air-gapped OverWatch runtime.

The runtime ships without a vuln catalog (it has a best-in-class MATCHING engine but BYO
feed). This build-host tool turns "BYO feed" into a turnkey, signed artifact: it merges
locally-STAGED OSV records + EPSS scores + CISA KEV into the exact ``{records, epss, kev,
exploits}`` JSON the scanner's ``--vuln-db`` loader and the hub already parse, and signs it
with a vendored Ed25519 detached signature so the runtime can verify provenance offline with
only a PUBLIC key.

ZERO-TELEMETRY BOUNDARY (important): this module reads ONLY local files — it imports no
network primitive and shells out to nothing, so it passes the repo's zero-telemetry tripwire
even though it lives under scripts/. The actual internet FETCH of OSV/EPSS/KEV is done by
``scripts/build_vulndb_bundle.sh`` (curl, in bash — outside the .py tripwire), exactly like
the existing ``build_offline_bundle.sh`` pip-download pattern. The air-gapped runtime NEVER
fetches; it only loads (and optionally verifies) a local signed bundle.

Subcommands:
  build   stage OSV/EPSS/KEV files -> merged feed JSON (+ a manifest)
  keygen  emit an Ed25519 keypair (private seed stays offline; ship only the .pub)
  sign    write a detached Ed25519 signature over a file
  verify  check a detached signature (exit 0 ok / 1 bad) — same check the runtime does
"""
from __future__ import annotations

import argparse
import glob
import gzip
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aws_ed25519  # noqa: E402  (vendored, pure-stdlib)

FORMAT_VERSION = 1

# The ecosystems the matching engine can actually hit (aws_sidescan OS-distro + language
# ecosystems). Anything else is dead weight the matcher never touches. Matched by the base
# before ':' (so "Debian:12", "Ubuntu:22.04", "Alpine:v3.18" all resolve to their distro).
DEFAULT_ECOSYSTEMS = {
    "debian", "ubuntu", "alpine", "red hat", "rocky linux", "almalinux",
    "amazon linux", "centos", "fedora", "opensuse", "suse",
    "npm", "pypi", "go", "rubygems", "crates.io", "maven",
}


def _eco_base(ecosystem: str) -> str:
    return (ecosystem or "").split(":", 1)[0].strip().lower()


def _open_maybe_gzip(path: str):
    with open(path, "rb") as fh:
        head = fh.read(2)
    if path.endswith(".gz") or head == b"\x1f\x8b":
        return gzip.open(path, "rt", encoding="utf-8")
    return open(path, "rt", encoding="utf-8")


# ── OSV loading (records passed through BYTE-EXACT; never rewrite ecosystem strings) ──
def _record_in_scope(rec: dict, ecosystems: set) -> bool:
    for aff in rec.get("affected", []) or []:
        if _eco_base((aff.get("package") or {}).get("ecosystem", "")) in ecosystems:
            return True
    return False


def _iter_osv_json(blob: str):
    """Yield OSV record dicts from a JSON blob that is either one record or a list."""
    data = json.loads(blob)
    if isinstance(data, list):
        yield from (r for r in data if isinstance(r, dict))
    elif isinstance(data, dict):
        yield data


def load_osv(path: str, ecosystems: set) -> list:
    """Load OSV records from a file or directory. Accepts individual .json records/lists and
    OSV bulk ``all.zip`` archives (each zip member a record). Drops withdrawn + out-of-scope
    records; keeps the rest verbatim (the matcher needs byte-exact package.ecosystem)."""
    records: list = []
    seen_ids: set = set()

    def _add(rec: dict):
        if not isinstance(rec, dict) or rec.get("withdrawn"):
            return
        if not _record_in_scope(rec, ecosystems):
            return
        rid = rec.get("id")
        if rid and rid in seen_ids:
            return
        if rid:
            seen_ids.add(rid)
        records.append(rec)

    files = []
    if os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, "**", "*.json"), recursive=True) +
                       glob.glob(os.path.join(path, "**", "*.zip"), recursive=True))
    else:
        files = [path]
    for f in files:
        if f.endswith(".zip"):
            import zipfile
            with zipfile.ZipFile(f) as z:
                for name in z.namelist():
                    if not name.endswith(".json"):
                        continue
                    try:
                        for rec in _iter_osv_json(z.read(name).decode("utf-8")):
                            _add(rec)
                    except Exception:
                        continue                     # a corrupt member is skipped, never fatal
        else:
            try:
                for rec in _iter_osv_json(open(f, encoding="utf-8").read()):
                    _add(rec)
            except Exception:
                continue
    return records


def load_epss(path: str) -> dict:
    """Parse a FIRST.org EPSS CSV (optionally gzip): comment lines start with '#', then a
    ``cve,epss,percentile`` header, then rows. Returns {cve: epss_float}."""
    out: dict = {}
    with _open_maybe_gzip(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or line.lower().startswith("cve,"):
                continue
            parts = line.split(",")
            if len(parts) >= 2 and parts[0].upper().startswith("CVE-"):
                try:
                    out[parts[0].strip()] = float(parts[1])
                except ValueError:
                    continue
    return out


def load_kev(path: str) -> list:
    """CISA KEV catalog (JSON): {vulnerabilities: [{cveID, ...}]}. Returns [cveID]."""
    data = json.loads(open(path, encoding="utf-8").read())
    out, seen = [], set()
    for v in data.get("vulnerabilities", []) if isinstance(data, dict) else []:
        cid = (v or {}).get("cveID")
        if cid and cid not in seen:
            seen.add(cid)
            out.append(cid)
    return out


def load_exploits(path: str) -> list:
    """Operator-supplied exploit-available set: a JSON list, or newline/CSV CVE ids."""
    text = open(path, encoding="utf-8").read().strip()
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return [str(x) for x in data]
    except Exception:
        pass
    ids = []
    for tok in text.replace(",", "\n").splitlines():
        tok = tok.strip()
        if tok.upper().startswith("CVE-"):
            ids.append(tok)
    return ids


def assemble(records: list, epss: dict, kev: list, exploits: list) -> dict:
    return {"records": records, "epss": epss, "kev": sorted(set(kev)),
            "exploits": sorted(set(exploits))}


def _write_json(obj, path: str) -> bytes:
    """Write compact, key-sorted JSON (reproducible bytes) and return what was written."""
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    with open(path, "wb") as fh:
        fh.write(data)
    return data


# ── subcommands ───────────────────────────────────────────────────────────────
def cmd_build(a) -> int:
    ecosystems = ({e.strip().lower() for e in a.ecosystems.split(",") if e.strip()}
                  if a.ecosystems else DEFAULT_ECOSYSTEMS)
    records = load_osv(a.osv, ecosystems) if a.osv else []
    epss = load_epss(a.epss) if a.epss else {}
    kev = load_kev(a.kev) if a.kev else []
    exploits = load_exploits(a.exploits) if a.exploits else []
    feed = assemble(records, epss, kev, exploits)
    data = _write_json(feed, a.out)
    manifest = {
        "format_version": FORMAT_VERSION,
        "ecosystems": sorted(ecosystems),
        "record_count": len(records),
        "epss_count": len(epss),
        "kev_count": len(feed["kev"]),
        "exploit_count": len(feed["exploits"]),
        "feed_bytes": len(data),
        "feed_sha256": hashlib.sha256(data).hexdigest(),
    }
    _write_json(manifest, a.out + ".manifest.json")
    print(f"wrote {a.out} ({len(records)} records, {len(epss)} EPSS, {len(feed['kev'])} KEV, "
          f"{len(feed['exploits'])} exploits, {len(data)} bytes)")
    print(f"      sha256 {manifest['feed_sha256']}")
    if a.key:
        return _sign_file(a.key, a.out, a.out + ".sig")
    return 0


def cmd_keygen(a) -> int:
    seed = os.urandom(32)
    pub = aws_ed25519.publickey(seed)
    with open(a.out_prefix + ".key", "w", encoding="utf-8") as fh:
        fh.write(seed.hex() + "\n")
    with open(a.out_prefix + ".pub", "w", encoding="utf-8") as fh:
        fh.write(pub.hex() + "\n")
    try:
        os.chmod(a.out_prefix + ".key", 0o600)       # best-effort; no-op on Windows
    except Exception:
        pass
    print(f"private seed -> {a.out_prefix}.key  (KEEP OFFLINE — never ship this)")
    print(f"public key   -> {a.out_prefix}.pub  (pin this in the runtime image)")
    print(f"public key   = {pub.hex()}")
    return 0


def _read_hex(path: str) -> bytes:
    return bytes.fromhex(open(path, encoding="utf-8").read().strip())


def _sign_file(key_path: str, in_path: str, sig_path: str) -> int:
    seed = _read_hex(key_path)
    sig = aws_ed25519.sign(seed, open(in_path, "rb").read())
    with open(sig_path, "w", encoding="utf-8") as fh:
        fh.write(sig.hex() + "\n")
    print(f"signed {in_path} -> {sig_path}")
    return 0


def cmd_sign(a) -> int:
    return _sign_file(a.key, a.infile, a.sig or (a.infile + ".sig"))


def cmd_verify(a) -> int:
    pub = _read_hex(a.pub)
    sig = _read_hex(a.sig or (a.infile + ".sig"))
    ok = aws_ed25519.verify(pub, open(a.infile, "rb").read(), sig)
    print("OK: signature valid" if ok else "FAIL: signature invalid")
    return 0 if ok else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="overwatch-vulndb", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="assemble a signed offline feed from staged OSV/EPSS/KEV")
    b.add_argument("--osv", help="OSV file or directory (records/lists/*.zip bulk archives)")
    b.add_argument("--epss", help="FIRST.org EPSS CSV (optionally .gz)")
    b.add_argument("--kev", help="CISA KEV catalog JSON")
    b.add_argument("--exploits", help="optional exploit-available CVE list (json/txt)")
    b.add_argument("--ecosystems", help="comma list overriding the engine-matched default set")
    b.add_argument("--out", default="overwatch-vulndb.json", help="output feed JSON path")
    b.add_argument("--key", help="Ed25519 private seed (hex file) to also sign the feed")
    b.set_defaults(fn=cmd_build)

    k = sub.add_parser("keygen", help="generate an Ed25519 signing keypair")
    k.add_argument("--out-prefix", default="overwatch-vulndb-key", help="writes <prefix>.key + .pub")
    k.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("sign", help="write a detached Ed25519 signature over a file")
    s.add_argument("--key", required=True, help="Ed25519 private seed (hex file)")
    s.add_argument("--in", dest="infile", required=True)
    s.add_argument("--sig", help="signature output path (default <in>.sig)")
    s.set_defaults(fn=cmd_sign)

    v = sub.add_parser("verify", help="verify a detached signature (same check as the runtime)")
    v.add_argument("--pub", required=True, help="Ed25519 public key (hex file)")
    v.add_argument("--in", dest="infile", required=True)
    v.add_argument("--sig", help="signature path (default <in>.sig)")
    v.set_defaults(fn=cmd_verify)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
