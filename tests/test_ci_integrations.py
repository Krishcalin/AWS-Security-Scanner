"""The integrations that name a module by PATH rather than importing it.

Workflows, a composite action, the VS Code extension and the offline-bundle
script all reference modules as FILES. No import rewrite touches them, and the
rest of the suite cannot see them, so when the flat root became engine/ + hub/ +
store/ every one of them broke in a way that produced no failing test:

  * a workflow `paths:` filter naming a file that no longer exists does not
    error -- the job simply stops running
  * the IaC gate exits with ::error:: only when someone runs it
  * `grep VERSION aws_live_scanner.py` returns empty, so the bundle is built and
    named with a blank version

The workflow YAML check is here for a different reason: extractor-fs-validation
was committed with a `run:` one-liner containing ": ", which is a mapping
separator in a plain scalar. That made the whole FILE unparseable, so GitHub ran
nothing -- and nothing said so.
"""
from __future__ import annotations

import io
import json
import os
import re

import pytest

from _layout import ROOT, module_path

WORKFLOWS = os.path.join(ROOT, ".github", "workflows")


def _workflow_files():
    files = [os.path.join(WORKFLOWS, f) for f in sorted(os.listdir(WORKFLOWS))
             if f.endswith((".yml", ".yaml"))]
    assert files, "no workflow files found -- the walk is broken"
    return files


@pytest.mark.parametrize("path", _workflow_files(), ids=os.path.basename)
def test_every_workflow_is_parseable_yaml(path):
    """An unparseable workflow is not a broken step, it is no CI at all."""
    yaml = pytest.importorskip("yaml")
    with io.open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh.read())
    assert isinstance(doc, dict) and doc.get("jobs"), (
        f"{os.path.basename(path)} parsed but declares no jobs")


@pytest.mark.parametrize("path", _workflow_files(), ids=os.path.basename)
def test_workflow_path_filters_point_at_files_that_exist(path):
    """A `paths:` entry naming a moved file silently disables the trigger."""
    yaml = pytest.importorskip("yaml")
    with io.open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh.read())
    # `on` is the YAML 1.1 boolean True when unquoted, which is how GitHub writes it.
    triggers = doc.get("on", doc.get(True, {})) or {}
    missing = []
    for event in ("push", "pull_request"):
        spec = triggers.get(event) or {}
        if not isinstance(spec, dict):
            continue
        for pattern in spec.get("paths", []) or []:
            if any(ch in pattern for ch in "*?["):
                continue                       # a glob, not a literal path
            if not os.path.exists(os.path.join(ROOT, pattern)):
                missing.append(pattern)
    assert not missing, (
        f"{os.path.basename(path)} filters on paths that do not exist: {missing}. "
        f"The job will never run again, and nothing will report that.")


def test_the_full_suite_actually_runs_in_ci():
    """The gap this file exists because of: ~5,500 tests that never ran on a push.

    Asserted as a property of the workflows rather than trusted to habit -- a
    suite nobody runs is indistinguishable from a suite that passes.
    """
    yaml = pytest.importorskip("yaml")
    runs_whole_suite = False
    for path in _workflow_files():
        with io.open(path, encoding="utf-8") as fh:
            body = fh.read()
        if re.search(r"pytest\s+tests\b(?!/)", body):
            doc = yaml.safe_load(body)
            triggers = doc.get("on", doc.get(True, {})) or {}
            if "push" in triggers or "pull_request" in triggers:
                runs_whole_suite = True
    assert runs_whole_suite, (
        "no workflow runs `pytest tests` on push or pull_request. Running one "
        "test file is how a Windows-only hash and an uninstallable requirements "
        "file both survived in this repo.")


def test_ci_covers_both_operating_systems():
    """This repo is written on Windows and shipped on Linux. The frozen-hash
    defect existed only across that gap, so one OS is not coverage."""
    yaml = pytest.importorskip("yaml")
    seen = set()
    for path in _workflow_files():
        with io.open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh.read())
        for job in (doc.get("jobs") or {}).values():
            matrix = ((job.get("strategy") or {}).get("matrix") or {})
            for value in matrix.get("os", []) or []:
                seen.add(str(value).split("-")[0])
            runs_on = job.get("runs-on")
            if isinstance(runs_on, str) and "${{" not in runs_on:
                seen.add(runs_on.split("-")[0])
    assert {"ubuntu", "windows"} <= seen, (
        f"CI runs on {sorted(seen)}; both ubuntu and windows are needed.")


def test_the_iac_gate_can_find_the_scanner():
    """The composite action locates the scanner by path and hard-errors if it
    cannot. Its first candidate must be where the file actually is."""
    path = os.path.join(ROOT, ".github", "actions", "overwatch-iac-gate",
                        "entrypoint.sh")
    with io.open(path, encoding="utf-8") as fh:
        body = fh.read()
    assert "engine/aws_offline_scanner.py" in body, (
        "the IaC gate still looks for the scanner at the old repo-root path")
    assert os.path.isfile(module_path("aws_offline_scanner.py"))


def test_the_offline_bundle_can_read_the_version():
    """VERSION is grepped out of the scanner source to name the tarball. A wrong
    path yields an EMPTY version and a bundle called overwatch-airgap-.tar.gz."""
    with io.open(os.path.join(ROOT, "scripts", "build_offline_bundle.sh"),
                 encoding="utf-8") as fh:
        script = fh.read()
    m = re.search(r"grep -m1 '\^VERSION' (\S+)", script)
    assert m, "the version probe changed shape; update this test with it"
    target = os.path.join(ROOT, m.group(1))
    assert os.path.isfile(target), f"the bundle greps {m.group(1)}, which is missing"
    with io.open(target, encoding="utf-8") as fh:
        source = fh.read()
    assert re.search(r'^VERSION\s*=\s*"[^"]+"', source, re.M), (
        "no VERSION line in the file the bundle script greps")


def test_the_vscode_extension_defaults_to_a_real_path():
    with io.open(os.path.join(ROOT, "ide", "vscode", "package.json"),
                 encoding="utf-8") as fh:
        pkg = json.load(fh)
    props = (pkg["contributes"]["configuration"]["properties"])
    default = props["overwatch.scannerPath"]["default"]
    assert os.path.isfile(os.path.join(ROOT, default)), (
        f"the extension defaults scannerPath to {default!r}, which does not exist")
