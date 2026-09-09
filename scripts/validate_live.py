#!/usr/bin/env python3
"""Live-account validation harness for aws_live_scanner.

The unit tests use hand-mocked boto3 responses, so they cannot catch drift between
our parsing and the *real* AWS API response shapes (e.g. IAM policy documents
arriving as URL-encoded strings vs dicts, paginator keys, etc.).

This harness runs a SAFE, READ-ONLY subset of the scanner against a real account
and reports whether the response shapes parsed cleanly. It makes only
describe/get/list calls (SecurityAudit policy) — it never mutates anything.

Usage:
    pip install -r requirements.txt
    python scripts/validate_live.py [--region eu-west-1]   # ALL sections (the point)
    python scripts/validate_live.py --quick                # credential smoke test only
    python scripts/validate_live.py --sections IAMPRIVESC,EBS,ACM

WHAT TO LOOK AT IN THE OUTPUT. `[FAIL]` lines are unambiguous — a section raised. The
three `[NOTE]` blocks are the ones that need somebody who knows the account:

  * SILENT SECTIONS. A section that produced nothing is either a service this account
    does not use or a shape we misread, and those are indistinguishable from here.
  * NOT EVALUATED. Refused reads, with the exact grant that would close each one. This
    is not a clean result and must not be read as one.
  * FAILED READS. Throttling or permissions during the scan.

Exit code 0 = validation passed, 1 = a section raised or parsing looked wrong.
"""
import argparse
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.aws_live_scanner import (  # noqa: E402
    AWSLiveScanner, HAS_BOTO3, SECTIONS, evaluate_privesc_scoped, VERSION,
)

#: THE DEFAULT IS NOW EVERY SECTION, and the change is the point of this harness.
#: It used to be five, which is ~5% of the product: the other 89 sections had never
#: had a single response shape checked against real AWS, while the suite reported
#: 400+ checks "proven" against mocks that the check authors wrote themselves.
#: `tests/test_aws_api_contract.py` closed the cheap half of that offline (operation
#: names and top-level response members, against botocore's models) and found two real
#: bugs doing it. This is the half that needs an account: fields that only appear on
#: real resources, pagination under load, and throttling.
#:
#: `--quick` keeps the old five for a fast credential smoke test.
QUICK_SECTIONS = ["IAMPRIVESC", "IAM", "EBS", "ACM", "ELB"]
DEFAULT_SECTIONS = list(SECTIONS)


def main() -> int:
    ap = argparse.ArgumentParser(description="Live validation harness for aws_live_scanner")
    ap.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "eu-west-1"))
    ap.add_argument("--sections", default=None,
                    help="Comma-separated sections to validate (default: all %d)"
                         % len(DEFAULT_SECTIONS))
    ap.add_argument("--quick", action="store_true",
                    help="Only the five highest-signal sections (%s) — a credential "
                         "smoke test, NOT a validation of the product"
                         % ", ".join(QUICK_SECTIONS))
    args = ap.parse_args()
    if args.sections is None:
        args.sections = ",".join(QUICK_SECTIONS if args.quick else DEFAULT_SECTIONS)

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
    silent = []
    for section in sections:
        produced = by_section.get(section, 0)
        errs = [r for r in unhandled if r.section == section]
        if errs:
            print(f"[FAIL] {section}: {errs[0].message}")
            ok = False
        elif produced == 0:
            silent.append(section)
        else:
            print(f"[ OK ] {section}: {produced} results, no unhandled exception")

    # ── the three things a FIRST real scan has to report ────────────────────
    # 1. Silence. A section that produced nothing is either a service this account
    #    does not use, or a section whose response shape we misread — and those look
    #    identical from here. Naming them is what makes the difference checkable by a
    #    human who knows the account; hiding them is how drift stays invisible.
    if silent:
        print(f"\n[NOTE] {len(silent)} section(s) produced no results at all. Each is "
              f"either a service this account does not use, or a shape we misread —\n"
              f"       these look the same from here, so check them against what you "
              f"know is deployed:")
        for name in silent:
            print(f"       - {name}")

    # 2. What could not be evaluated, and the grant that would fix it. A denied read is
    #    not a clean result, and the ledger already records which action was refused.
    cov = getattr(scanner, "_coverage", None)
    not_evaluated = dict(getattr(cov, "not_evaluated", {}) or {})
    missing_actions = sorted(set(getattr(cov, "missing_actions", []) or []))
    if not_evaluated:
        print(f"\n[NOTE] {len(not_evaluated)} check(s) NOT EVALUATED — refused, not "
              f"clean. Grant these to close the gap:")
        for action in missing_actions:
            print(f"       - {action}")

    # 3. Findings that say outright that a read failed. `_read_failed` writes these,
    #    and on a real account they are the throttling and permission signal.
    unread = [r for r in scanner.results
              if r.status == "WARN" and "NOT EVALUATED" in (r.message or "")]
    if unread:
        print(f"\n[NOTE] {len(unread)} read(s) failed during the scan "
              f"(throttling or permissions). Sample:")
        for r in unread[:5]:
            print(f"       - {r.check_id}: {r.message[:110]}")

    print(f"\nSections run: {len(sections)}  |  results: {len(scanner.results)}  |  "
          f"silent: {len(silent)}  |  not evaluated: {len(not_evaluated)}")
    print("VALIDATION", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
