#!/usr/bin/env python3
"""Live-account validation harness for aws_live_scanner.

The unit tests use hand-mocked boto3 responses, so they cannot catch drift between
our parsing and the *real* AWS API response shapes (e.g. IAM policy documents
arriving as URL-encoded strings vs dicts, paginator keys, etc.).

This harness runs a SAFE, READ-ONLY subset of the scanner against a real account
and reports whether the response shapes parsed cleanly. It makes only
describe/get/list calls (SecurityAudit policy) — it never mutates anything.

Usage:
    pip install boto3
    python scripts/validate_live.py [--region eu-west-1]
    python scripts/validate_live.py --sections IAMPRIVESC,EBS,ACM

Exit code 0 = validation passed, 1 = a section raised or parsing looked wrong.
"""
import argparse
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aws_live_scanner import (  # noqa: E402
    AWSLiveScanner, HAS_BOTO3, evaluate_privesc_scoped, VERSION,
)

# Safe, high-signal default subset: the IAM privesc engine (validates policy-doc
# parsing — the shape most likely to drift) plus a few resource sections.
DEFAULT_SECTIONS = ["IAMPRIVESC", "IAM", "EBS", "ACM", "ELB"]


def main() -> int:
    ap = argparse.ArgumentParser(description="Live validation harness for aws_live_scanner")
    ap.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "eu-west-1"))
    ap.add_argument("--sections", default=",".join(DEFAULT_SECTIONS),
                    help="Comma-separated sections to validate")
    args = ap.parse_args()

    if not HAS_BOTO3:
        print("[FAIL] boto3 is not installed — run: pip install boto3")
        return 1

    import boto3
    from botocore.exceptions import NoCredentialsError, ClientError

    print(f"AWS live-scanner validation harness (scanner v{VERSION})")
    print(f"Region: {args.region}")

    # 1) Identity / credentials
    try:
        ident = boto3.client("sts", region_name=args.region).get_caller_identity()
        print(f"[ OK ] Authenticated as {ident['Arn']} (account {ident['Account']})")
    except (NoCredentialsError, ClientError) as e:
        print(f"[FAIL] Could not authenticate: {e}")
        return 1

    sections = [s.strip().upper() for s in args.sections.split(",") if s.strip()]
    scanner = AWSLiveScanner(region=args.region, verbose=False, sections=sections)
    scanner.account = ident["Account"]

    ok = True

    # 2) IAM principal collection + policy-document parsing (the key shape check)
    if "IAMPRIVESC" in sections:
        try:
            principals = scanner._get_iam_principals()
            n_stmts = sum(len(p["statements"]) for p in principals)
            n_findings = sum(len(evaluate_privesc_scoped(p["statements"]))
                             for p in principals)
            empty_parses = sum(
                1 for p in principals
                if not p["statements"] and (p["allow"] or p["deny"])
            )
            print(f"[ OK ] IAM principals enumerated: {len(principals)} "
                  f"({n_stmts} statements parsed)")
            print(f"[ OK ] Privesc findings (resource-aware): {n_findings}")
            if empty_parses:
                print(f"[WARN] {empty_parses} principal(s) had actions but no parsed "
                      f"statements — possible policy-doc shape drift")
                ok = False
        except Exception:
            print("[FAIL] IAM principal collection raised:")
            traceback.print_exc()
            ok = False

    # 3) Run the requested sections via the scanner's real orchestration.
    #    run() wraps each section in try/except and records an "Unhandled error in
    #    section ..." result on failure, so shape drift surfaces as such a result.
    try:
        scanner.run()
    except SystemExit:
        # run() calls sys.exit(2) only on auth/boto3 failure, already handled above
        pass
    except Exception:
        print("[FAIL] scanner.run() raised:")
        traceback.print_exc()
        return 1

    unhandled = [r for r in scanner.results
                 if r.message.startswith("Unhandled error in section")]
    by_section = {}
    for r in scanner.results:
        by_section.setdefault(r.section, 0)
        by_section[r.section] += 1
    for section in sections:
        produced = by_section.get(section, 0)
        errs = [r for r in unhandled if r.section == section]
        if errs:
            print(f"[FAIL] {section}: {errs[0].message}")
            ok = False
        else:
            print(f"[ OK ] {section}: {produced} results, no unhandled exception")

    print("\nVALIDATION", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
