"""Repo-root data files must still be found from inside a package.

Three modules locate a REPO-ROOT directory from their own __file__. When the 109
flat root modules moved into engine/ + hub/ + store/ they each went one level
down, and every one of these paths silently started pointing at a directory that
does not exist:

    engine/compliance_crosswalk  -> compliance/crosswalk.json
    engine/aws_live_scanner      -> docs/overwatch-mark-96.png
    hub/cnapp_server             -> frontend/dist

Only the first fails loudly. The logo read is wrapped in `except Exception`, so
a wrong path just removes the logo from every report with nothing in the log;
and the static dir is normally supplied by CNAPP_STATIC_DIR, so a wrong default
stays hidden until someone runs without it and gets a 404 console -- which has
already happened once here, from a mangled env var rather than from this code.

Neither of those announces itself, so they are pinned here instead.
"""
from __future__ import annotations

import ast
import io
import os

import pytest

from _layout import ROOT, module_path


def _assigned_paths(filename: str) -> list:
    """Every os.path.join(...) in the module that starts from __file__.

    Read from the AST rather than executed: cnapp_server's are inside factory
    functions that build a whole application, and aws_live_scanner's is inside a
    try/except that would swallow the very failure being tested.
    """
    with io.open(module_path(filename), encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "join"):
            continue
        literals = [a.value for a in node.args
                    if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        if not literals:
            continue
        src = ast.dump(node.args[0]) if node.args else ""
        if "__file__" in src:
            depth = src.count("'dirname'")
            out.append((literals, depth))
    return out


CASES = [
    ("compliance_crosswalk.py", ["compliance", "crosswalk.json"]),
    ("aws_live_scanner.py", ["docs", "overwatch-mark-96.png"]),
    ("cnapp_server.py", ["frontend", "dist"]),
]


@pytest.mark.parametrize("filename,tail", CASES)
def test_the_path_climbs_out_of_its_package(filename, tail):
    """Two dirname() calls, not one: up out of engine/ or hub/, then to the root."""
    matches = [(lits, depth) for lits, depth in _assigned_paths(filename)
               if lits == tail]
    assert matches, f"{filename} no longer joins {tail} from __file__"
    for _, depth in matches:
        assert depth >= 2, (
            f"{filename} resolves {tail} with {depth} dirname() call(s). The "
            f"module lives one level down in a package, so a repo-root path "
            f"needs two -- with one it points inside the package, where nothing "
            f"is.")


@pytest.mark.parametrize("tail", [c[1] for c in CASES])
def test_the_target_actually_exists_at_the_repo_root(tail):
    """The other half: the path is well-formed AND the thing is really there."""
    target = os.path.join(ROOT, *tail)
    assert os.path.exists(target), (
        f"{'/'.join(tail)} is missing from the repository root. Either it moved "
        f"or the module pointing at it is now wrong.")


def test_the_crosswalk_loads_through_its_default_path():
    """The one case that can be exercised end to end without building an app."""
    from engine import compliance_crosswalk

    assert os.path.isfile(compliance_crosswalk._DEFAULT_PATH)
    assert compliance_crosswalk.get_crosswalk(), "crosswalk loaded but is empty"


def test_the_report_logo_is_readable():
    """aws_live_scanner swallows this read, so assert the file is reachable at
    the path the module computes rather than trusting the module not to raise."""
    logo = os.path.join(ROOT, "docs", "overwatch-mark-96.png")
    assert os.path.isfile(logo)
    with io.open(logo, "rb") as fh:
        assert fh.read(8).startswith(b"\x89PNG"), "not a PNG any more"
