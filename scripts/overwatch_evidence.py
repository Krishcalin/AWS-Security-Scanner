#!/usr/bin/env python3
"""overwatch-evidence — wrap a compliance evidence pack into a signed, verifiable bundle.

The scanner writes ``ai_compliance_evidence.json``: a control-by-control record that
includes, uniquely, **which controls the scan never reached**. On its own that file is a
printout — it asserts things about a scan and nothing about it can be checked once it
leaves the machine that made it.

This turns it into an artifact:

    overwatch-evidence keygen --out-prefix acme-evidence
    overwatch-evidence sign   --key acme-evidence.key --in ai_compliance_evidence.json
    overwatch-evidence verify --in ai_compliance_evidence.bundle.json --pub acme-evidence.pub

THE VERIFIER IS THE POINT
--------------------------
``verify`` is deliberately runnable by someone who has no OverWatch install, no AWS
access and no network: it is stdlib-only Python plus two vendored modules. An auditor
should not have to trust the tool that produced the evidence in order to check the
evidence. Hand them the bundle, the public key, and this file.

It also exits non-zero on failure and prints WHICH section changed, because "invalid" is
not a useful answer to an auditor holding a bundle somebody may have edited.

WHAT SIGNING DOES NOT DO
-------------------------
It does not make an incomplete scan complete. The attestation inside every bundle says so
in its own words, and that text is itself covered by the signature so it cannot be edited
out. The coverage manifest is likewise inside the signed root: stripping "these controls
were never assessed" from a bundle breaks verification, which is the single property this
whole design exists to provide.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import stat
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_ed25519          # noqa: E402  (vendored, pure-stdlib)
from engine import aws_evidence_bundle as eb   # noqa: E402

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
    GREEN = RED = YELLOW = DIM = RESET = ""

#: Env var an operator can use instead of --key, so a CI job never puts the seed in argv
#: (where it would land in the process table and in shell history).
KEY_ENV = "OVERWATCH_EVIDENCE_SIGNING_KEY"


def _read_seed(path: str | None) -> bytes:
    """Load the signing seed from a file or the environment. Never echoed."""
    if path:
        with open(path, "r", encoding="utf-8") as f:
            return eb.seed_from_text(f.read())
    env = os.environ.get(KEY_ENV)
    if env:
        return eb.seed_from_text(env)
    raise SystemExit(
        f"{RED}no signing key{RESET}: pass --key <file> or set {KEY_ENV} "
        f"(base64-encoded 32-byte Ed25519 seed)")


def _load_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise SystemExit(f"{RED}not found{RESET}: {path}")
    except json.JSONDecodeError as e:
        raise SystemExit(f"{RED}not valid JSON{RESET}: {path} ({e})")


# ── keygen ──────────────────────────────────────────────────────────────────
def cmd_keygen(args) -> int:
    seed = os.urandom(32)
    pub = aws_ed25519.publickey(seed)
    key_path, pub_path = args.out_prefix + ".key", args.out_prefix + ".pub"
    for path in (key_path, pub_path):
        if os.path.exists(path) and not args.force:
            # Overwriting a signing key silently would invalidate every bundle already
            # issued under it, with no way to tell which ones.
            raise SystemExit(
                f"{RED}refusing to overwrite{RESET} {path} -- pass --force if you are sure. "
                f"Replacing a key invalidates nothing already signed, but nothing signed "
                f"with the old key will verify against the new one.")

    # 0600 before writing, not after: a world-readable window is still a leak.
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(base64.b64encode(seed).decode("ascii") + "\n")
    with open(pub_path, "w", encoding="utf-8") as f:
        f.write(base64.b64encode(pub).decode("ascii") + "\n")

    # Report what the filesystem ACTUALLY did rather than what we asked for. POSIX mode
    # bits are advisory on Windows -- os.open(..., 0o600) there leaves the file readable
    # by other local accounts, and printing "mode 0600" regardless would tell an operator
    # their signing key is protected when it is not.
    mode = stat.S_IMODE(os.stat(key_path).st_mode)
    if mode & 0o077:
        note = (f"mode {mode:04o} - this filesystem did not honour 0600, so restrict it "
                f"yourself (icacls/chmod) and keep it out of git")
        colour = YELLOW
    else:
        note = "mode 0600 - keep it out of git"
        colour = DIM
    print(f"{GREEN}[+]{RESET} private seed  {key_path}  {colour}({note}){RESET}")
    print(f"{GREEN}[+]{RESET} public key    {pub_path}  {DIM}(hand this to your auditor){RESET}")
    return 0


# ── sign ────────────────────────────────────────────────────────────────────
def cmd_sign(args) -> int:
    seed = _read_seed(args.key)
    pack = _load_json(args.infile)

    # The scanner writes coverage INSIDE the pack. Lift it into its own signed section so
    # its removal is detectable as a named tampering rather than as a generic mismatch.
    coverage = pack.get("coverage") if isinstance(pack, dict) else None
    bundle = eb.build_bundle(
        pack,
        coverage=coverage,
        permissions=pack.get("permissions") if isinstance(pack, dict) else None,
        scope={"account": (pack or {}).get("account"),
               "crosswalk_digest": (pack or {}).get("crosswalk_digest")},
        producer={"tool": "overwatch-evidence", "bundle_version": eb.BUNDLE_VERSION},
        generated_at=args.at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        seed=seed,
    )
    out = args.out or (os.path.splitext(args.infile)[0] + ".bundle.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, sort_keys=True)
        f.write("\n")

    print(f"{GREEN}[+]{RESET} signed bundle {out}")
    print(f"    root        {bundle['root']}")
    print(f"    public key  {bundle['signature']['public_key']}")
    print(f"{DIM}    generated_at is this host's clock, not a trusted timestamp.{RESET}")
    return 0


# ── verify ──────────────────────────────────────────────────────────────────
def cmd_verify(args) -> int:
    bundle = _load_json(args.infile)
    expect = None
    if args.pub:
        with open(args.pub, "r", encoding="utf-8") as f:
            expect = f.read().strip()

    r = eb.verify_bundle(bundle, expect_public_key=expect)

    if r["ok"] and r["signed"] and expect:
        print(f"{GREEN}[OK]{RESET} bundle verifies and is signed by the expected key "
              f"{r['signed_by'][:16]}...")
    elif r["ok"] and r["signed"]:
        # WITHOUT --pub this proves only that SOME key signed it -- and a forger who
        # signs their own edited bundle satisfies exactly this. Printing a bare [OK]
        # here would be the most dangerous output this tool could produce, because it
        # is the case an auditor in a hurry is most likely to hit.
        print(f"{YELLOW}[OK, UNAUTHENTICATED]{RESET} bundle is internally consistent and "
              f"signed by {r['signed_by'][:16]}...")
        print(f"{YELLOW}    You did not pass --pub, so this does NOT prove who produced "
              f"it.{RESET}")
        print(f"{DIM}    Anyone can sign an edited bundle with their own key and it will "
              f"print this. Re-run with --pub <the key you trust>.{RESET}")
    elif r["ok"]:
        # Internally consistent but nobody vouches for it. Not a pass, not a failure.
        print(f"{YELLOW}[UNSIGNED]{RESET} contents are internally consistent, but the "
              f"bundle carries no signature -- its origin is unproven.")
        if bundle.get("unsigned_reason"):
            print(f"{DIM}    {bundle['unsigned_reason']}{RESET}")
    else:
        print(f"{RED}[FAIL]{RESET} bundle did not verify")
        for p in r["problems"]:
            print(f"    - {p}")
        if r["tampered_sections"]:
            print(f"{RED}    edited section(s): {', '.join(r['tampered_sections'])}{RESET}")

    if not args.quiet and isinstance(bundle, dict) and bundle.get("attestation"):
        print()
        print(f"{DIM}{bundle['attestation']}{RESET}")

    # Exit code is the machine-readable answer, and it must not call an unauthenticated
    # pass a success: 0 = verified against an EXPECTED key, 1 = failed, 2 = internally
    # consistent but the signer was not checked (unsigned, or verified without --pub).
    # A CI gate that wants "signed by us or bust" checks for 0 only.
    if not r["ok"]:
        return 1
    return 0 if (r["signed"] and expect) else 2


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="overwatch-evidence",
                                description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="generate an Ed25519 signing keypair")
    k.add_argument("--out-prefix", default="overwatch-evidence-key",
                   help="writes <prefix>.key (0600) + <prefix>.pub")
    k.add_argument("--force", action="store_true", help="overwrite an existing keypair")
    k.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("sign", help="wrap an evidence pack into a signed bundle")
    s.add_argument("--in", dest="infile", required=True,
                   help="ai_compliance_evidence.json from a scan")
    s.add_argument("--key", help=f"seed file (default: ${KEY_ENV})")
    s.add_argument("--out", help="bundle path (default <in>.bundle.json)")
    s.add_argument("--at", help="override generated_at (ISO 8601) for reproducible builds")
    s.set_defaults(fn=cmd_sign)

    v = sub.add_parser("verify",
                       help="check a bundle -- stdlib only, no OverWatch install needed")
    v.add_argument("--in", dest="infile", required=True)
    v.add_argument("--pub", help="expected public key file; without it, the signer is "
                                 "unauthenticated (any key verifies)")
    v.add_argument("--quiet", action="store_true", help="suppress the attestation text")
    v.set_defaults(fn=cmd_verify)

    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except eb.BundleError as e:
        print(f"{RED}[FAIL]{RESET} {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
