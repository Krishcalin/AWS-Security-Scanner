"""Where a module's source file lives, now that the root is three packages.

Many tests read a module's SOURCE rather than importing it -- the zero-telemetry
tripwire, the mutation-surface ratchet, the check-map lockstep. Before the
engine/hub/store split those all said os.path.join(ROOT, "aws_thing.py"), which
is a hardcoded fact about the layout in ~30 files.

Resolving the name instead means a module can move between layers without
touching a single test, and -- more to the point -- a module that has moved is
reported as MOVED rather than as a file that does not exist.

    from _layout import module_path
    src = open(module_path("aws_kube.py")).read()
"""
from __future__ import annotations

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Ordered so the smallest, most specific layer is searched first. A basename is
#: unique across the three today, and test_layering pins that it stays that way.
LAYERS = ("store", "hub", "engine")


def layer_dirs() -> list:
    return [os.path.join(ROOT, name) for name in LAYERS]


def module_path(filename: str) -> str:
    """Absolute path to a module's source, searched across the layers.

    Raises rather than returning a missing path: a test that reads a module and
    silently gets nothing back is the vacuous pass this codebase exists to
    refuse. If the module was deleted, the failure should say so here.
    """
    if not filename.endswith(".py"):
        filename += ".py"
    for layer in LAYERS:
        candidate = os.path.join(ROOT, layer, filename)
        if os.path.isfile(candidate):
            return candidate
    raise FileNotFoundError(
        "%s is in none of %s. If it was renamed or deleted, the test naming it "
        "needs updating; if it was added, it needs a layer."
        % (filename, "/".join(LAYERS)))


def iter_modules(prefixes=("aws_", "cnapp_", "compliance_")):
    """(filename, source) for every module in every layer.

    Replaces os.listdir(ROOT) in the sweeps that walk "every module". Those did
    not recurse, so after the split they would have found nothing and passed
    while inspecting nothing.
    """
    out = []
    for layer in LAYERS:
        d = os.path.join(ROOT, layer)
        for name in sorted(os.listdir(d)):
            if not name.endswith(".py") or name == "__init__.py":
                continue
            if prefixes and not name.startswith(tuple(prefixes)):
                continue
            with open(os.path.join(d, name), encoding="utf-8") as fh:
                out.append((name, fh.read()))
    assert len(out) >= 50, (
        "only %d modules found across %s -- the walk is broken, not the "
        "codebase" % (len(out), LAYERS))
    return out


def module_files() -> list:
    """Absolute paths of every module in every layer."""
    paths = []
    for layer in LAYERS:
        d = os.path.join(ROOT, layer)
        paths += [os.path.join(d, n) for n in sorted(os.listdir(d))
                  if n.endswith(".py") and n != "__init__.py"]
    assert len(paths) >= 50, (
        "only %d module files found -- the walk is broken" % len(paths))
    return paths


def layer_of(module: str) -> str:
    """Which layer a module lives in ("engine" / "hub" / "store").

    For building an import statement in a subprocess probe, where the module
    name is a runtime value and no import rewrite can reach it.
    """
    name = module if module.endswith(".py") else module + ".py"
    for layer in LAYERS:
        if os.path.isfile(os.path.join(ROOT, layer, name)):
            return layer
    raise FileNotFoundError("%s is in none of %s" % (name, "/".join(LAYERS)))
