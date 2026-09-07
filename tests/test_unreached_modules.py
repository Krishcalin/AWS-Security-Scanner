"""Every first-party module is imported by something, or is named here and why.

THE FAILURE MODE THIS EXISTS TO STOP. The v3.0.0 readiness assessment recorded it
plainly: "of the seven modules 2.38.0 added, four had zero non-test consumers", and
"built-and-unreached is a liability that demos as capability". A module with tests
and no caller passes CI, appears in CLAUDE.md as a delivered bullet, and is counted
by a reader as working software. `aws_sidescan_lambda` was the sharpest case: it
shipped complete, `docs/OVERWATCH_VULN_ROADMAP.md` ticked its check `LMB-07` ✅, and
LMB-07 was registered in none of the four metadata maps and emitted by no code path,
so the check could not fire and the tick was false.

Finding that took a deliberate audit. Nothing in the build said it, which is the
actual defect — so this is the tripwire, built the way this repo already builds them
(`test_check_maps_lockstep.py`'s frozen-backlog ratchet, `test_zero_telemetry.py`'s
egress allowlist): coverage BY DEFAULT, plus one visible list that can only shrink.

  * a module imported by nothing outside its own tests fails this test,
  * unless it is an ENTRY POINT (a process, not a library) or is named in UNREACHED,
  * a NEW orphan can never be added, because it is in neither set,
  * and an UNREACHED entry that has gained a caller also fails, so the list cannot
    rot into fiction the way an un-maintained waiver list does.

TO SHRINK THE LIST: wire the module, or delete it and its tests. Both are progress.
Adding an entry is not — that is the thing being ratcheted against.
"""
from __future__ import annotations

import ast
import io
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Packages whose modules must each be reached by something.
PACKAGES = ("engine", "hub", "store")

#: Everywhere a first-party import may legitimately come from. `tests/` is
#: deliberately absent: a module reached only by its own tests is exactly what this
#: file is looking for.
IMPORTER_DIRS = ("engine", "hub", "store", "scripts", "deploy", "ide", "compliance")

#: Processes, not libraries. Nothing imports these because they are invoked, and
#: `test_an_entry_point_is_actually_runnable` stops the category being used as a
#: parking space for a library that simply has no caller.
ENTRY_POINTS = {
    "aws_offline_scanner": "the pre-deploy IaC static scanner — its own CLI, "
                           "referenced by deploy/ and .github/",
    "cnapp_mcp": "the MCP server, run as a process",
}

#: The debt. Each of these is real, tested, documented code that nothing calls.
#: Recorded rather than deleted because three encode ratified review-defect fixes
#: (D5, D6) whose removal is a product decision, not an engineering one — see
#: docs/DECISIONS.md. What is NOT acceptable is presenting them as delivered
#: capability; CLAUDE.md marks each as library-only for that reason.
UNREACHED = {
    "aws_guardrail":
        "FR-5 / defect D5 (a gate that is down does what its strictest configured "
        "mode would have done). No CI entry point and no ExposureGate producer.",
    "aws_trend":
        "FR-4 / defect D6 (a forecast refuses rather than labels below three usable "
        "periods). The console's trend comes from aws_scorecard.Trend, a simple "
        "prior-vs-current comparison; this is the II-C version and nothing routes to it.",
    "aws_ingest_credexp":
        "credential-exposure ingest. No CLI flag, no API route, no console surface.",
    "cnapp_marketplace_metering":
        "marketplace usage metering. deploy/marketplace/ documents it as OPT-IN "
        "optional code; no hub billing path calls it.",
    "cnapp_worker":
        "the hosted platform's async scan-job execution and scheduler "
        "(run_scan_job / drain_once / scheduler_tick). Imported only by tests, and "
        "with no __main__ it cannot be run as a process either — so the documented "
        "async scan path is unreachable in both directions.",
}


def _modules() -> dict:
    out = {}
    for pkg in PACKAGES:
        d = os.path.join(ROOT, pkg)
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if f.endswith(".py") and f != "__init__.py":
                out[f[:-3]] = "%s/%s" % (pkg, f)
    return out


def _imported_names(path: str) -> set:
    """Names this file imports. AST, not text: `aws_scorecard` mentions `aws_trend`
    in a docstring cross-reference, and a grep-based version counts that as a
    consumer — which is precisely the false clean this file must not produce."""
    try:
        tree = ast.parse(io.open(path, encoding="utf-8").read(), path)
    except (OSError, SyntaxError):
        return set()
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                names.add(a.name.split(".")[-1])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module.split(".")[-1])
            for a in node.names:
                names.add(a.name)
    return names


def _importers() -> dict:
    mods = _modules()
    found = {}
    for d in IMPORTER_DIRS:
        top = os.path.join(ROOT, d)
        if not os.path.isdir(top):
            continue
        for dirpath, dirs, files in os.walk(top):
            dirs[:] = [x for x in dirs if x not in ("__pycache__", "tests")]
            for f in files:
                if not f.endswith(".py"):
                    continue
                stem = f[:-3]
                for name in _imported_names(os.path.join(dirpath, f)):
                    if name in mods and name != stem:
                        found.setdefault(name, set()).add(
                            os.path.relpath(os.path.join(dirpath, f), ROOT)
                            .replace("\\", "/"))
    return found


@pytest.fixture(scope="module")
def reached():
    return _importers()


def test_no_module_is_unreached_without_being_declared(reached):
    """The ratchet. A module nothing imports is either a process, or debt somebody
    wrote down — never a surprise."""
    orphans = sorted(m for m in _modules()
                     if m not in reached
                     and m not in ENTRY_POINTS
                     and m not in UNREACHED)
    assert not orphans, (
        "%s imported by nothing outside tests/. Wire it, delete it with its tests, "
        "or — if it is a process rather than a library — add it to ENTRY_POINTS "
        "with a reason. Do NOT add it to UNREACHED to make this pass: that list is "
        "the debt being paid down, not a waiver list." % (orphans,))


def test_no_declared_orphan_has_quietly_gained_a_caller(reached):
    """The other half of the ratchet, and the half that keeps the list honest. A
    waiver list nobody prunes stops describing the codebase and starts describing
    its history. `aws_sidescan_lambda` belonged here until its producer was written;
    it is absent now because it has five callers, and that is what shrinking looks
    like."""
    fixed = sorted(m for m in UNREACHED if m in reached)
    assert not fixed, (
        "%s now has callers and should be removed from UNREACHED: %s"
        % (fixed, {m: sorted(reached[m]) for m in fixed}))


def test_an_entry_point_is_actually_runnable():
    """Stops ENTRY_POINTS becoming a quieter UNREACHED. A process has a `__main__`;
    a library parked here to silence the ratchet does not. `cnapp_worker` is the
    reason this test exists — it is a library with no caller AND no `__main__`, so
    it belongs in UNREACHED and cannot be reclassified out of it."""
    mods = _modules()
    for name in sorted(ENTRY_POINTS):
        assert name in mods, "%s is declared an entry point but does not exist" % name
        src = io.open(os.path.join(ROOT, mods[name]), encoding="utf-8").read()
        assert '__name__ == "__main__"' in src or "__name__ == '__main__'" in src, (
            "%s is declared an entry point but has no __main__ guard, so nothing "
            "can run it and nothing imports it" % name)


def test_every_declared_orphan_still_exists():
    """Deleting a module without deleting its entry here leaves the list describing
    files that are gone."""
    mods = _modules()
    missing = sorted(m for m in UNREACHED if m not in mods)
    assert not missing, "%s named in UNREACHED but no longer exists" % (missing,)


def test_the_debt_is_stated_with_a_reason():
    """An entry with no reason is a waiver. Each has to say what the module is and
    what is missing, so the next reader can judge wire-versus-delete without
    repeating the audit."""
    for name, why in sorted(UNREACHED.items()):
        assert len(why) > 60, "%s: reason too thin to act on" % name
