#!/usr/bin/env python3
"""Which checks does the suite actually make fire, and at what status?

Two steps, deliberately:

    OVERWATCH_RECORD_CHECKS=fired.json python -m pytest tests/ -q
    python scripts/check_firing.py --from fired.json

WHY NOT ONE STEP. The first draft ran pytest itself via ``subprocess`` and
``tests/test_zero_telemetry.py`` refused it: `scripts/` is deliberately inside the
tripwire's scan ("so a telemetry call cannot hide in a subpackage"), and the egress
allowlist holds exactly three genuine operator-opt-in seams. Adding a developer tool
to that list to make a build pass would cost the control its meaning, so the tool
lost the dependency instead. No script in this repo imports ``subprocess``, and that
stays true.

WHY THIS IS NOT A STATIC ANALYSIS, which is the whole reason it exists. "Which checks
can produce a finding" reads like a question you answer by grepping for ``_add``, and
it is not. A check id reaches ``_add`` as a literal, a bare variable (``fid``), a
subscript (``f["id"]``) or a conditional, and every one of the scanner's 90 sections
uses at least one non-literal form. Three successive greps gave three confident and
different wrong answers -- 76, then 48, then 42 checks "that can never FAIL" -- before
the fourth showed the honest number was 0, because nothing is provable that way.

So the truth comes from running it. ``tests/conftest.py`` wraps
``AWSLiveScanner._add`` -- the single point where every finding in the product is
constructed -- and records every ``(check_id, status)`` the suite emits.

WHAT THE OUTPUT MEANS, and the distinction that carries the value:

  * PROVEN FAILING -- some test drives this check to an actual FAIL. It works.
  * RUNS BUT NEVER FAILS -- it emits, but no test has made it report a problem. Not
    automatically a defect (a check may legitimately only warn), but ``_add`` reads
    severity, compliance and remediation from the maps **only for a FAIL**: a WARN is
    forced to LOW and carries no remediation, an INFO carries neither. So a check
    registered CRITICAL that only ever WARNs never renders what the catalogue
    advertises for it.
  * NEVER OBSERVED -- no test made it emit anything. THREAT-02 is the known case:
    registered in all four maps, given a full remediation write-up, counted in the
    published total, and emitted by no code path anywhere.

The sibling SAP product has had this for a while (``docs/CHECK_FIRING.md``, "819 of
819 proven"). OverWatch had no equivalent, which is exactly why THREAT-02 went
unnoticed.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

OUT = os.path.join(ROOT, "docs", "CHECK_FIRING.md")

HEADER = """# Check firing reference

<!-- GENERATED FILE - DO NOT EDIT BY HAND.
     Produced by scripts/check_firing.py from a real suite run:
       OVERWATCH_RECORD_CHECKS=fired.json python -m pytest tests/ -q
       python scripts/check_firing.py --from fired.json -->

Every registered check, and whether the test suite has ever made it emit a finding.
Derived by recording `AWSLiveScanner._add` across the whole suite, because the
question cannot be answered by reading the source - a check id reaches `_add` as a
literal, a variable, a subscript or a conditional, and all 90 sections use at least
one non-literal form.

`_add` reads severity, compliance and remediation from the catalogue **only for a
FAIL**. A WARN is forced to severity LOW and carries no remediation, and an INFO
carries neither - so a check that never fails never renders what the catalogue
advertises for it.

"""


def build(observed) -> str:
    from engine.aws_live_scanner import CHECK_SEVERITY

    status_of = {}
    for cid, st in observed:
        status_of.setdefault(cid, set()).add(st)

    registered = sorted(CHECK_SEVERITY)
    failing, soft, unseen = [], [], []
    for cid in registered:
        st = status_of.get(cid)
        if not st:
            unseen.append(cid)
        elif "FAIL" in st:
            failing.append(cid)
        else:
            soft.append((cid, CHECK_SEVERITY[cid], "/".join(sorted(st))))

    # Emitted but absent from CHECK_SEVERITY: such a finding renders with the default
    # severity and no remediation, because `_add` looks both up by check id.
    unregistered = sorted(c for c in status_of if c not in CHECK_SEVERITY)

    out = [HEADER]
    out.append("**%d registered checks.** %d are proven to FAIL in the suite; %d run "
               "but have never been driven to a failure; %d were never observed at "
               "all.\n" % (len(registered), len(failing), len(soft), len(unseen)))

    out.append("\n## Never observed\n")
    if unseen:
        out.append("No test makes these emit anything. Each is registered in all four "
                   "metadata maps and counted in the catalogue total.\n")
        for cid in unseen:
            out.append("- `%s` (declared %s)" % (cid, CHECK_SEVERITY[cid]))
    else:
        out.append("None - every registered check emits something somewhere.")

    out.append("\n\n## Runs, but never fails\n")
    if soft:
        out.append("These emit only WARN/INFO/PASS in the suite. Where the declared "
                   "severity is above LOW, that severity has never been rendered.\n")
        out.append("| Check | Declared | Observed |")
        out.append("|---|---|---|")
        for cid, sev, st in soft:
            out.append("| `%s` | %s | %s |" % (cid, sev, st))
    else:
        out.append("None - every check that runs has been driven to a failure "
                   "somewhere in the suite.")

    if unregistered:
        # The sharp case is an unregistered id that reaches FAIL: `_add` looks up BOTH
        # severity and remediation by check id, so such a finding renders at the
        # default MEDIUM with no remediation at all. Stated explicitly rather than
        # left for a reader to work out, so a test can assert on it.
        failing_unreg = sorted(c for c in unregistered if "FAIL" in status_of[c])
        out.append("\n\n## Emitted but not registered\n")
        out.append("A finding whose id the catalogue does not know renders with the "
                   "default severity and no remediation.\n")
        out.append("**Reaching FAIL: %s**\n"
                   % (", ".join("`%s`" % c for c in failing_unreg)
                      if failing_unreg else "none - all are INFO/WARN/PASS markers"))
        for cid in unregistered:
            out.append("- `%s` (%s)" % (cid, "/".join(sorted(status_of[cid]))))

    out.append("")
    return "\n".join(out)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Regenerate docs/CHECK_FIRING.md.")
    p.add_argument("--from", dest="src", required=True,
                   help="a recording written by OVERWATCH_RECORD_CHECKS")
    p.add_argument("--print", action="store_true", help="stdout instead of the doc")
    args = p.parse_args(argv)

    if not os.path.exists(args.src):
        raise SystemExit(
            "no recording at %s. Produce one with:\n"
            "  OVERWATCH_RECORD_CHECKS=%s python -m pytest tests/ -q" % (args.src,
                                                                        args.src))
    observed = json.load(io.open(args.src, encoding="utf-8"))
    text = build(observed)
    if args.print:
        print(text)
        return 0
    io.open(OUT, "w", encoding="utf-8", newline="").write(text)
    print("wrote %s (%d observations)" % (os.path.relpath(OUT, ROOT), len(observed)))
    return 0


if __name__ == "__main__":                            # pragma: no cover
    raise SystemExit(main())
