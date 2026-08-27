"""Registry projections must not depend on import order.

WHY THIS EXISTS. `aws_checkdef` is populated as a side effect of importing the modules
that declare checks, and the three consumer modules — `aws_live_scanner`,
`aws_finding_detail`, `aws_perm_ledger` — merge that registry into their maps at import
time. So a consumer that fails to import a declaring module gets a *partial* registry,
and which projections exist depends on what happened to be imported first.

That is not hypothetical. `MCP-06` was declared in `aws_mcp`, and neither
`aws_finding_detail` nor `aws_perm_ledger` imported it. Whether the check had a detail
page depended entirely on import order, and the first verification imported `aws_mcp`
first — so it reported everything present. Only the full suite, importing modules in a
different order, disagreed.

The check below imports each consumer **alone, in a fresh interpreter**, which is the
condition that failed. A registry merge is invisible to the dict-literal ratchets, so
this is the only place the coupling can be caught.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: consumer module -> the map it must populate for every registered check
CONSUMERS = {
    "aws_live_scanner": ("CHECK_SEVERITY", "COMPLIANCE_MAP", "REMEDIATION_MAP"),
    "aws_finding_detail": ("FINDING_DETAIL",),
    "aws_perm_ledger": ("REQUIREMENTS",),
}

PROBE = """
import json, sys
sys.path.insert(0, {root!r})
import {module} as consumer
from engine import aws_checkdef as C
maps = {maps!r}
missing = {{}}
for name in maps:
    target = getattr(consumer, name)
    absent = sorted(k for k in C.REGISTRY if k not in target)
    if absent:
        missing[name] = absent
print(json.dumps({{"registered": len(C.REGISTRY), "missing": missing}}))
"""


def _probe(module, maps):
    """Import ONE consumer in a fresh interpreter and report what it is missing."""
    out = subprocess.run(
        [sys.executable, "-c", PROBE.format(root=ROOT, module=module, maps=maps)],
        capture_output=True, text=True, cwd=ROOT, timeout=180)
    assert out.returncode == 0, f"{module} failed to import alone:\n{out.stderr[-2000:]}"
    return json.loads(out.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("module,maps", sorted(CONSUMERS.items()))
def test_a_consumer_imported_alone_has_every_registered_projection(module, maps):
    """The exact condition that failed for MCP-06.

    If this fails, the named module does not import whichever module declares the listed
    checks — add the import next to the other declaring-module imports, above the merge."""
    r = _probe(module, maps)
    assert r["registered"] > 0, f"{module} imported an EMPTY registry"
    assert not r["missing"], (
        f"{module} imported alone is missing registered checks: {r['missing']}. "
        f"The registry is populated by importing the modules that declare checks, so a "
        f"consumer that does not import one of them merges a partial registry — and "
        f"whether the projection exists then depends on import order.")


@pytest.mark.parametrize("module", sorted(CONSUMERS))
def test_every_consumer_sees_the_same_registry_size(module):
    """A consumer that sees fewer registered checks than another is importing less."""
    sizes = {m: _probe(m, CONSUMERS[m])["registered"] for m in CONSUMERS}
    assert len(set(sizes.values())) == 1, (
        f"consumers disagree on how many checks are registered: {sizes}. They must each "
        f"import every declaring module, or their maps diverge by import order.")


def test_the_declaring_modules_are_imported_by_every_consumer():
    """Stated as source rather than behaviour, so the fix is obvious when it fails."""
    import io
    import re
    declaring = set()
    for name in sorted(os.listdir(ROOT)):
        if not name.startswith("aws_") or not name.endswith(".py"):
            continue
        src = io.open(os.path.join(ROOT, name), encoding="utf-8").read()
        if re.search(r"^CHECKS\s*=\s*_cd\.register\(", src, re.M):
            declaring.add(name[:-3])
    assert declaring, "no declaring modules found — has the registry pattern changed?"
    for consumer in CONSUMERS:
        src = io.open(os.path.join(ROOT, consumer + ".py"), encoding="utf-8").read()
        imported = set(re.findall(r"^import (aws_\w+)", src, re.M))
        missing = sorted(declaring - imported)
        assert not missing, (
            f"{consumer}.py does not import {missing}, which declare checks via "
            f"aws_checkdef. Add the import above the merge call.")
