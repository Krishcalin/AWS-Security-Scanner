"""Phase 4 · slice 4.6 — the model artifact as executable code.

A serialized model is not data. Pickle encodes *instructions*, and `REDUCE` calls
whatever the stream names — so loading an artifact runs code with the credentials of
whatever loaded it. A SageMaker endpoint pulling a poisoned `.pt` from S3 executes
attacker code holding the execution role.

The safety property this file exists to defend: **nothing here ever unpickles.**
`pickletools.genops` walks the opcode stream without running it, and a test below builds
a pickle whose `__reduce__` would fire and proves it does not. A scanner that unpickled an
artifact to check whether unpickling it is safe would *be* the vulnerability, wearing a
security label.

The second property is restraint. Almost every real PyTorch model contains `REDUCE` —
that is how the format rebuilds a tensor. Calling every model malicious is how a scanner
gets switched off, so `EXECUTABLE` and `MALICIOUS` are separate verdicts and only a global
with no explainable reason to be in a model earns the stronger one.
"""
from __future__ import annotations

import io
import os
import pickle
import pickletools
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_modelartifact as MA


# ── the artifact sources ────────────────────────────────────────────────────
def test_all_three_source_locations_are_found():
    """Missing any one means missing an artifact that executes."""
    c = {"ModelDataUrl": "s3://b/legacy.tar.gz",
         "ModelDataSource": {"S3DataSource": {"S3Uri": "s3://b/model/", "ETag": "abc"}},
         "AdditionalModelDataSources": [
             {"ChannelName": "lora", "S3DataSource": {"S3Uri": "s3://b/lora/"}}]}
    got = {s["channel"]: s["uri"] for s in MA.artifact_sources(c)}
    assert got == {"ModelDataUrl": "s3://b/legacy.tar.gz",
                   "ModelDataSource": "s3://b/model/", "lora": "s3://b/lora/"}


def test_an_etag_marks_the_reference_as_pinned():
    c = {"ModelDataSource": {"S3DataSource": {"S3Uri": "s3://b/m", "ETag": "abc"}}}
    assert MA.artifact_sources(c)[0]["pinned"] is True


def test_no_etag_is_unpinned():
    """Without one, what runs is whatever sits at the URI at deploy time — the rug-pull
    shape from slice 3.3 applied to artifacts."""
    c = {"ModelDataSource": {"S3DataSource": {"S3Uri": "s3://b/m"}}}
    assert MA.artifact_sources(c)[0]["pinned"] is False


def test_the_legacy_url_can_never_be_pinned():
    """ModelDataUrl has no ETag field at all, so it is unpinned by construction rather
    than by omission — worth reporting as such."""
    assert MA.artifact_sources({"ModelDataUrl": "s3://b/m"})[0]["pinned"] is False


def test_a_container_with_no_artifact_yields_nothing():
    assert MA.artifact_sources({"Image": "img"}) == []


# ── format detection ────────────────────────────────────────────────────────
def test_a_raw_pickle_is_detected_from_its_bytes():
    f = MA.artifact_format("model.bin", pickle.dumps({"a": 1}))
    assert f["format"] == "pickle" and f["executes"] is True


def test_a_zip_is_detected_as_executing():
    """PyTorch .pt archives hold a pickle inside."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("archive/data.pkl", pickle.dumps({"a": 1}))
    f = MA.artifact_format("model.pt", buf.getvalue())
    assert f["format"] == "zip" and f["executes"] is True


def test_bytes_beat_the_filename():
    """A .safetensors holding a pickle is not safe. Trusting the name over the content
    is how a scanner is talked out of a finding."""
    f = MA.artifact_format("weights.safetensors", pickle.dumps({"a": 1}))
    assert f["executes"] is True and f["safe_format"] is False


def test_safetensors_is_recognised_as_a_safe_format():
    """Detecting one is a PASS worth reporting: it is the remediation for everything
    else in this module."""
    f = MA.artifact_format("weights.safetensors", None)
    assert f["safe_format"] is True and f["executes"] is False


def test_a_pickle_suffix_with_no_bytes_is_still_flagged():
    assert MA.artifact_format("model.pkl", None)["executes"] is True


# ── the scan never executes ─────────────────────────────────────────────────
class _Evil:
    def __reduce__(self):
        # If anything unpickles this, the file it writes is the proof.
        return (open, ("SHOULD_NEVER_EXIST.txt", "w"))


def test_scanning_a_malicious_pickle_does_not_execute_it(tmp_path):
    """The load-bearing safety test. A scanner that unpickled an artifact to check
    whether unpickling it is safe would BE the vulnerability."""
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        blob = pickle.dumps(_Evil())
        scan = MA.scan_opcodes(blob)
        assert scan["parsed"] is True
        assert not os.path.exists("SHOULD_NEVER_EXIST.txt"), "the pickle was executed"
    finally:
        os.chdir(cwd)


def test_the_module_never_calls_pickle_load():
    """Structural, not incidental. Checked against executable code with docstrings
    stripped, so the module can explain itself without tripping its own guard."""
    import ast
    import inspect
    tree = ast.parse(inspect.getsource(MA))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            b = node.body
            if (b and isinstance(b[0], ast.Expr) and isinstance(b[0].value, ast.Constant)
                    and isinstance(b[0].value.value, str)):
                b.pop(0)
    code = ast.unparse(tree)
    for banned in ("pickle.load", "pickle.loads", "Unpickler", "torch.load",
                   "joblib.load", "numpy.load"):
        assert banned not in code, f"{banned} appears in executable code"


# ── what the scan finds ─────────────────────────────────────────────────────
def test_a_dangerous_global_is_named():
    blob = pickle.dumps(_Evil())
    scan = MA.scan_opcodes(blob)
    # _io.open, NOT builtins.open. The first authoring of the danger table listed the
    # latter -- a pair pickle never emits -- so the commonest payload would have been
    # missed by a table that read correctly.
    assert "_io.open" in scan["dangerous_globals"]
    assert MA.verdict_for(scan) == "MALICIOUS"


def test_the_danger_table_matches_what_pickle_actually_emits():
    """Authored from observation rather than memory, and pinned so it stays that way.
    Each pair below is what CPython emits when the callable is pickled."""
    import builtins
    import os
    import subprocess

    def emitted(fn):
        class E:
            def __reduce__(self):
                return (fn, ())
        ops = list(pickletools.genops(pickle.dumps(E())))
        strs = [a for op, a, _ in ops
                if op.name.endswith("BINUNICODE") or op.name == "UNICODE"]
        return tuple(strs[:2])

    for fn in (open, os.popen, subprocess.Popen, builtins.eval, builtins.exec,
               builtins.__import__, os.system):
        mod, name = emitted(fn)
        assert name in MA.DANGEROUS_GLOBALS.get(mod, ()),             f"pickle emits {mod}.{name}, which the table does not name"


def test_both_platform_spellings_of_os_system_are_covered():
    """os.system pickles as posix.system on Linux and nt.system on Windows. The platform
    that matters is the one the ARTIFACT was built on, not the one the scanner runs on:
    a Linux-built payload must be caught by a Windows scan and the reverse."""
    for mod in ("posix", "nt"):
        assert "system" in MA.DANGEROUS_GLOBALS[mod]


def test_stack_global_is_resolved_from_the_preceding_strings():
    """Protocol 4 pushes the module and name as separate strings rather than passing
    them as an argument, so a scanner reading only op arguments finds nothing."""
    blob = pickle.dumps(_Evil(), protocol=4)
    scan = MA.scan_opcodes(blob)
    assert "STACK_GLOBAL" in scan["opcodes"]
    assert scan["dangerous_globals"], "STACK_GLOBAL operands were not tracked"


def test_an_ordinary_model_is_executable_but_not_malicious():
    """Almost every real PyTorch model contains REDUCE — that is how the format rebuilds
    a tensor. Calling them all malicious is how a scanner gets switched off."""
    import collections
    blob = pickle.dumps(collections.OrderedDict([("w", [1, 2, 3])]))
    scan = MA.scan_opcodes(blob)
    assert scan["parsed"] is True
    assert MA.verdict_for(scan) in ("EXECUTABLE", "INERT")
    assert scan["dangerous_globals"] == []


def test_a_plain_data_pickle_is_inert():
    scan = MA.scan_opcodes(pickle.dumps({"a": 1, "b": [2, 3]}))
    assert MA.verdict_for(scan) == "INERT"


def test_a_pickle_inside_a_zip_is_scanned():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("archive/data.pkl", pickle.dumps(_Evil()))
    scan = MA.scan_opcodes(buf.getvalue())
    assert MA.verdict_for(scan) == "MALICIOUS"


def test_an_unparseable_stream_is_unknown_not_clean():
    """A scanner that treated an unparseable artifact as clean would be defeated by
    appending one junk byte."""
    scan = MA.scan_opcodes(b"\x00\x01\x02not a pickle at all")
    assert scan["parsed"] is False
    assert MA.verdict_for(scan) == "UNKNOWN"


def test_no_data_is_unknown():
    assert MA.verdict_for(MA.scan_opcodes(None)) == "UNKNOWN"
    assert MA.verdict_for(MA.scan_opcodes(b"")) == "UNKNOWN"


def test_a_zip_with_no_pickle_member_is_unknown():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("weights.safetensors", b"{}")
    assert MA.scan_opcodes(buf.getvalue())["parsed"] is False


def test_the_read_is_bounded():
    """An opt-in data crossing that reads unbounded objects becomes an egress bill."""
    assert MA.MAX_SCAN_BYTES <= 16 * 1024 * 1024


# ── the description ─────────────────────────────────────────────────────────
def test_an_externally_writable_source_says_what_it_permits():
    line = MA.describe_source({"uri": "s3://b/m", "channel": "ModelDataSource",
                               "pinned": True}, write_scope="public")
    assert "executes code on the next deploy" in line


def test_an_unpinned_source_says_what_loads():
    line = MA.describe_source({"uri": "s3://b/m", "channel": "ModelDataSource",
                               "pinned": False})
    assert "whatever sits at that URI at deploy time" in line


def test_a_pinned_internal_source_describes_as_nothing():
    assert MA.describe_source({"uri": "s3://b/m", "channel": "x", "pinned": True}) == ""


# ── robustness ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", [None, {}, "nope", 7,
                                 {"ModelDataSource": "x"},
                                 {"AdditionalModelDataSources": "x"}])
def test_nothing_raises_on_malformed_input(bad):
    MA.artifact_sources(bad if isinstance(bad, dict) else None)
    MA.artifact_format(bad if isinstance(bad, str) else None, None)
    MA.describe_source(bad if isinstance(bad, dict) else None)


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    assert not re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests)\b",
                          inspect.getsource(MA), re.M)
