"""The engine/hub/store boundary is a rule, not a filing convention.

Dependencies point downward only:

    hub/    -> engine/, store/
    engine/ ->          store/
    store/  ->  (neither)

Before the split, 109 modules sat flat in the repository root and nothing
prevented any of them importing any other. A directory layout alone would not
have changed that -- it would only have made the tangle harder to see. This file
is what makes the arrows above true, so a violation fails here rather than
becoming a fact about the codebase that the diagram quietly stops describing.

Placement follows DEPENDENCIES, not filename prefixes: aws_registry_connectors
lives in hub/ and compliance_crosswalk in engine/. Where a name and its package
disagree, the package is the one that is checked.
"""
from __future__ import annotations

import ast
import io
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAYERS = ("store", "engine", "hub")

#: What each layer is allowed to import. Widening any of these sets is a
#: decision about the architecture, and should be made in a commit that says so.
ALLOWED = {
    "store": set(),
    "engine": {"store"},
    "hub": {"engine", "store"},
}

#: A layer with fewer modules than this means the walk is broken, not that the
#: codebase shrank -- the same vacuous-pass trap the root-walking guards had.
_MIN = {"store": 3, "engine": 50, "hub": 10}


def _modules(layer: str):
    d = os.path.join(ROOT, layer)
    found = [n for n in sorted(os.listdir(d))
             if n.endswith(".py") and n != "__init__.py"]
    assert len(found) >= _MIN[layer], (
        "only %d modules found in %s/ -- the walk is broken, so every check "
        "built on it would pass without inspecting anything"
        % (len(found), layer))
    return [(n, os.path.join(d, n)) for n in found]


def _layers_imported(path: str) -> set:
    """Which sibling layers this file imports, by any form.

    Reads the AST rather than the text so that a name inside a docstring, a
    comment or a string literal cannot be mistaken for an import -- and, more
    importantly, so that a real import cannot hide from a regex.
    """
    with io.open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), path)
    hits = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):            # import hub.cnapp_api [as x]
            for a in node.names:
                head = a.name.split(".")[0]
                if head in LAYERS:
                    hits.add(head)
        elif isinstance(node, ast.ImportFrom):      # from hub[.x] import y
            if node.level:                          # relative: same package
                continue
            if node.module:
                head = node.module.split(".")[0]
                if head in LAYERS:
                    hits.add(head)
    return hits


@pytest.mark.parametrize("layer", LAYERS)
def test_a_layer_imports_only_what_it_is_allowed_to(layer):
    offenders = {}
    for name, path in _modules(layer):
        illegal = _layers_imported(path) - ALLOWED[layer] - {layer}
        if illegal:
            offenders[name] = sorted(illegal)
    assert not offenders, (
        "%s/ may import %s, but these reach further:\n%s\n"
        "Dependencies point downward only (see docs/ARCHITECTURE.md). Either the "
        "module is in the wrong layer, or the thing it needs is."
        % (layer, sorted(ALLOWED[layer]) or "nothing",
           "\n".join("  %s -> %s" % (f, v) for f, v in sorted(offenders.items()))))


def test_store_is_the_bottom_of_the_stack():
    """Stated separately from the parametrised case because it is the property
    the third package exists for. The persistence trio is mutually recursive, so
    if it could reach upward the cycle would cross a package boundary -- strictly
    worse than the flat root this replaced."""
    for name, path in _modules("store"):
        assert not (_layers_imported(path) - {"store"}), (
            "%s reaches out of store/. The trio is mutually recursive; anything "
            "it imports is dragged into that cycle." % name)


def test_every_layer_is_a_package():
    for layer in LAYERS:
        init = os.path.join(ROOT, layer, "__init__.py")
        assert os.path.isfile(init), f"{layer}/ has no __init__.py"
        with io.open(init, encoding="utf-8") as fh:
            assert ast.get_docstring(ast.parse(fh.read())), (
                f"{layer}/__init__.py must say what the layer is for")


def test_no_python_modules_are_left_loose_in_the_root():
    """The point of the split. A module added to the root belongs to no layer,
    is checked by none of the rules above, and is how the flat root grew the
    first time."""
    loose = [n for n in sorted(os.listdir(ROOT))
             if n.endswith(".py") and n != "conftest.py"]
    assert not loose, (
        "python modules in the repository root: %s. Put each in engine/, hub/ or "
        "store/ -- see docs/ARCHITECTURE.md." % loose)
