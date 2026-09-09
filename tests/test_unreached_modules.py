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
    "cnapp_worker": "the hosted scan-queue drainer \u2014 `python -m hub.cnapp_worker`, "
                    "run by a cron/CronJob; also imported by cnapp_server.build_service "
                    "for its session factory",
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


def _used_names(path: str) -> dict:
    """{module: True} for every first-party module this file actually USES.

    THE HOLE THIS CLOSES. `aws_nhi` was imported by three production modules and
    called by none of them. It shipped complete -- five checks, a permission ledger,
    full write-ups, its own test file -- and could not fire, because nothing invoked
    it. `_imported_names` saw three importers and reported it reached, which is the
    one answer that made the defect invisible: from an import-based check, an unused
    import and a wired module look identical.

    The import was not pointless, either, which is why this needs its own pass rather
    than a stricter version of the other. `aws_nhi` registers its CheckDefs at import
    time, so importing it really does populate the four metadata maps -- the checks
    were registered, counted and documented while the logic behind them was
    unreachable. Registration is not execution.

    So: an attribute access on the module (`aws_nhi.nhi_findings`), or a use of a
    symbol imported from it. Assignment targets do not count -- rebinding a name is
    not using the module.
    """
    mods = _modules()
    try:
        tree = ast.parse(io.open(path, encoding="utf-8").read(), path)
    except (OSError, SyntaxError):
        return {}
    stem = os.path.basename(path)[:-3]
    alias = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            tail = node.module.split(".")[-1]
            for a in node.names:
                if tail in mods:
                    alias[a.asname or a.name] = tail
                elif a.name in mods:
                    alias[a.asname or a.name] = a.name
        elif isinstance(node, ast.Import):
            for a in node.names:
                tail = a.name.split(".")[-1]
                if tail in mods:
                    alias[a.asname or tail] = tail
    used = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            name = node.value.id
            mod = alias.get(name, name if name in mods else None)
            if mod and mod != stem:
                used[mod] = True
        elif isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Store):
            mod = alias.get(node.id)
            if mod and mod != stem:
                used[mod] = True
    return used


def _users() -> dict:
    """module -> files that USE it, as opposed to merely importing it."""
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
                path = os.path.join(dirpath, f)
                for name in _used_names(path):
                    if name in mods:
                        found.setdefault(name, set()).add(
                            os.path.relpath(path, ROOT).replace("\\", "/"))
    return found


def _declares_checks(path: str) -> bool:
    """Whether the module registers CheckDefs, i.e. puts ids in the catalogue."""
    try:
        src = io.open(path, encoding="utf-8").read()
    except OSError:
        return False
    return "checkdef" in src and ".register(" in src


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


@pytest.fixture(scope="module")
def used():
    return _users()


def test_a_module_that_declares_checks_is_actually_called(used):
    """THE aws_nhi RATCHET, and the sharpest form of the rule.

    A module that registers CheckDefs puts ids into the catalogue at import time --
    they are counted in the published total, carry compliance mappings and remediation
    write-ups, and appear to a reader as delivered coverage. If nothing then CALLS the
    module, every one of those checks is unfirable, and the product is advertising
    capability it does not have. That is what NHI-01..05 were: registered, documented,
    counted, and unreachable, for as long as the module had importers and no caller.
    """
    mods = _modules()
    declaring = sorted(m for m, rel in mods.items()
                       if _declares_checks(os.path.join(ROOT, rel)))
    assert declaring, "no module declares checks any more; this test needs rewriting"
    silent = [m for m in declaring if m not in used]
    assert not silent, (
        "%s registers checks in the catalogue but nothing calls it, so those checks "
        "cannot fire. Wire the module, or delete it with its check declarations -- do "
        "NOT leave registered-but-unreachable checks counted in the published total."
        % (silent,))


def test_no_module_is_imported_without_ever_being_used(used, reached):
    """The general form. An import is not a caller.

    `test_no_module_is_unreached_without_being_declared` asks whether somebody imports
    the module, and that question has a blind spot: an unused import satisfies it.
    `aws_nhi` sat in it for as long as it existed. ENTRY_POINTS and UNREACHED are
    excluded for the same reasons as above -- a process has no caller by definition,
    and declared debt is already written down.
    """
    orphans = sorted(m for m in _modules()
                     if m in reached
                     and m not in used
                     and m not in ENTRY_POINTS
                     and m not in UNREACHED)
    assert not orphans, (
        "%s is imported but never used -- no attribute access, no imported symbol. "
        "Either it is wired and this test is wrong, or it is dead weight that reads "
        "as delivered capability. An import for a registration side effect is still "
        "not a caller: aws_nhi registered five checks that way and none could fire."
        % (orphans,))


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
    its history. `aws_sidescan_lambda` belonged here until its producer was written,
    and `cnapp_worker` until it gained an entry point and a caller in
    `cnapp_server.build_service`. Both are absent now, and that is what shrinking
    looks like."""
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
