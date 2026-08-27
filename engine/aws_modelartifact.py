#!/usr/bin/env python3
"""aws_modelartifact.py — Phase 4 · slice 4.6: the model artifact as executable code.

A serialized model is not data. Python's pickle format encodes *instructions*, and
``REDUCE`` calls whatever callable the stream names — so loading a model artifact runs
code with the credentials of whatever loaded it. A SageMaker endpoint that pulls a
poisoned ``.pt`` from S3 executes attacker code holding the execution role. That is not a
theoretical class; it is the ordinary consequence of the format.

TWO HALVES, AND THEY ANSWER DIFFERENT QUESTIONS
------------------------------------------------
**Could the artifact be replaced?** — configuration, in-charter, and the higher-leverage
half. ``ModelDataUrl`` and ``ModelDataSource.S3Uri`` say where a container loads from. If
that bucket is writable by an external principal, whoever writes it gets code execution on
the next deploy without touching anything else. This is exactly `TFLOW-01`'s reasoning —
whoever can write the corpus writes what the model says — applied one layer down, to what
the model *is*.

And ``S3ModelDataSource`` carries an **``ETag``**. Without one the reference is *mutable*:
what runs is whatever sits at that URI at load time, and nothing in the account records
that it changed. That is the rug-pull shape from slice `3.3`, applied to artifacts.

**Is the artifact malicious?** — the data plane, opt-in, and a genuine charter crossing:
it needs ``s3:GetObject``, the action class FLOW-00 documents as deliberately excluded.
It ships in the FLOW-00 shape or not at all.

THE SCAN NEVER EXECUTES ANYTHING
---------------------------------
``pickletools.genops`` walks the opcode stream without running it. That was verified
rather than assumed: a pickle whose ``__reduce__`` calls ``print`` yields ``REDUCE`` and
``STACK_GLOBAL`` in the opcode list and prints nothing. **`pickle.load` is never called
here and a test asserts it never appears in executable code** — a scanner that unpickled
an artifact to check whether unpickling it is safe would be the whole vulnerability,
wearing a security label.

Only opcodes and the module/name pairs they reference are read. Tensor payloads are
skipped by construction: the interesting opcodes carry short strings, and nothing in this
module reads a ``BINBYTES`` argument.

Pure functions over bytes and dicts. No boto3, no network, no I/O.
"""
from __future__ import annotations

import io
import pickletools
import zipfile
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

__all__ = [
    "DANGEROUS_OPCODES", "DANGEROUS_GLOBALS", "SAFE_FORMATS", "PICKLE_SUFFIXES",
    "MAX_SCAN_BYTES", "artifact_sources", "artifact_format", "scan_opcodes",
    "verdict_for", "describe_source", "CONTENTS_NOT_READ",
]

#: Opcodes that can invoke a callable. GLOBAL/STACK_GLOBAL resolve a module attribute;
#: REDUCE/INST/OBJ/NEWOBJ call it. A pickle containing none of these cannot execute.
DANGEROUS_OPCODES: Tuple[str, ...] = (
    "GLOBAL", "STACK_GLOBAL", "REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD",
)

#: module -> names whose appearance in a pickle is not explainable as model data.
#: Deliberately a SHORT list of things with no legitimate reason to be in a serialized
#: model, rather than an attempt to enumerate every malicious import. The scan reports
#: every global it finds; these are the ones it will call out by name.
DANGEROUS_GLOBALS: Dict[str, Tuple[str, ...]] = {
    # Read off what pickle ACTUALLY emits, not from memory. The first authoring of this
    # table listed "builtins.open" -- a pair that never occurs, because `open` pickles
    # as **_io.open**. The most common malicious payload there is would have been
    # missed entirely by a table that looked right.
    "_io": ("open", "open_code"),
    # os.system pickles as **posix**.system on Linux and **nt**.system on Windows. Both
    # are listed because the platform that matters is the one the ARTIFACT was built on,
    # not the one the scanner runs on -- a Linux-built payload must be caught by a
    # Windows scan and the reverse.
    "posix": ("system", "popen", "execv", "execve", "spawnv", "remove", "unlink"),
    "nt": ("system", "popen", "execv", "execve", "spawnv", "remove", "unlink"),
    "os": ("system", "popen", "execv", "execve", "spawnv", "remove", "rename"),
    "subprocess": ("Popen", "run", "call", "check_call", "check_output", "getoutput"),
    "builtins": ("eval", "exec", "compile", "__import__", "getattr", "setattr"),
    "__builtin__": ("eval", "exec", "compile", "__import__", "getattr", "setattr"),
    "socket": ("socket", "create_connection"),
    "shutil": ("rmtree", "move", "copyfile"),
    "pty": ("spawn",),
    "importlib": ("import_module",),
    "webbrowser": ("open",),
    "runpy": ("_run_code", "run_path"),
}

#: Formats that cannot execute on load. Detecting one is a PASS worth reporting: it is
#: the remediation for everything else in this module.
SAFE_FORMATS: Tuple[str, ...] = ("safetensors", "onnx")

#: Suffixes whose contents are pickle or contain one.
PICKLE_SUFFIXES: Tuple[str, ...] = (
    ".pkl", ".pickle", ".pt", ".pth", ".bin", ".joblib", ".ckpt", ".model",
)

#: How much of an artifact to read. The opcode stream that matters sits at the start of
#: the pickle, and a bounded read is what keeps an opt-in data crossing from becoming an
#: unbounded egress bill. A truncated stream is reported as truncated, never as clean.
MAX_SCAN_BYTES = 8 * 1024 * 1024

CONTENTS_NOT_READ = (
    "OverWatch reads the artifact's OPCODE STREAM and never unpickles it: what the model "
    "weights contain is not a question this scan asks"
)


def _d(v) -> dict:
    return v if isinstance(v, dict) else {}


def artifact_sources(container: Optional[dict]) -> List[dict]:
    """Every S3 location one container loads a model from.

    Three places, and missing any of them means missing an artifact that executes:
    the legacy ``ModelDataUrl``, the modern ``ModelDataSource.S3DataSource``, and
    ``AdditionalModelDataSources`` — extra channels that load alongside the primary and
    are just as executable."""
    c = _d(container)
    out: List[dict] = []
    url = c.get("ModelDataUrl")
    if isinstance(url, str) and url:
        out.append({"uri": url, "channel": "ModelDataUrl", "etag": "",
                    "pinned": False, "compression": ""})
    s3 = _d(_d(c.get("ModelDataSource")).get("S3DataSource"))
    if s3.get("S3Uri"):
        out.append({"uri": s3["S3Uri"], "channel": "ModelDataSource",
                    "etag": s3.get("ETag") or "",
                    "pinned": bool(s3.get("ETag")),
                    "compression": s3.get("CompressionType") or ""})
    for extra in (c.get("AdditionalModelDataSources") or []):
        if not isinstance(extra, dict):
            continue
        e3 = _d(extra.get("S3DataSource"))
        if e3.get("S3Uri"):
            out.append({"uri": e3["S3Uri"],
                        "channel": extra.get("ChannelName") or "additional",
                        "etag": e3.get("ETag") or "",
                        "pinned": bool(e3.get("ETag")),
                        "compression": e3.get("CompressionType") or ""})
    return out


def artifact_format(uri: Optional[str], head: Optional[bytes] = None) -> dict:
    """What kind of artifact this is, from its name and its first bytes.

    The bytes win where they disagree with the suffix: a ``.bin`` holding a safetensors
    header is safe, and a ``.safetensors`` holding a pickle is not. Trusting the name
    over the content is how a scanner is talked out of a finding."""
    name = (uri or "").lower()
    fmt, executes, why = "unknown", None, ""
    if isinstance(head, (bytes, bytearray)) and head:
        b = bytes(head[:8])
        if b[:2] == b"PK":
            fmt, executes = "zip", True
            why = "a ZIP container — PyTorch .pt archives hold a pickle inside"
        elif b[:1] in (b"\x80", b"(", b"]", b"}", b"c") and b[:1] != b"":
            fmt, executes = "pickle", True
            why = "a raw pickle stream"
        elif b[:4].isdigit() or b[:1] == b"{":
            fmt, executes = "safetensors", False
            why = "a safetensors header — a format that cannot execute on load"
    if fmt == "unknown":
        if any(s in name for s in (".safetensors",)):
            fmt, executes, why = "safetensors", False, "named as safetensors"
        elif ".onnx" in name:
            fmt, executes, why = "onnx", False, "named as ONNX"
        elif any(name.endswith(s) for s in PICKLE_SUFFIXES):
            fmt, executes, why = "pickle-suffixed", True, "a pickle-bearing suffix"
    return {"format": fmt, "executes": executes, "why": why,
            "safe_format": fmt in SAFE_FORMATS}


def _inner_pickle(data: bytes) -> bytes:
    """The pickle inside a PyTorch ZIP archive, or the data unchanged.

    Reads only the member NAMED like a pickle and only its bytes — the tensor members
    are never opened. A truncated archive raises, which the caller reports as
    unreadable rather than as clean."""
    if data[:2] != b"PK":
        return data
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for name in z.namelist():
            if name.endswith(("data.pkl", ".pkl", ".pickle")):
                with z.open(name) as fh:
                    return fh.read(MAX_SCAN_BYTES)
    return b""


def scan_opcodes(data: Optional[bytes]) -> dict:
    """Static opcode scan. NEVER unpickles.

    ``pickletools.genops`` walks the stream without running it — verified, not assumed.
    A stream that fails to parse is reported as ``parsed=False``: a scanner that treated
    an unparseable artifact as clean would be defeated by appending one junk byte."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        return {"parsed": False, "reason": "no data", "opcodes": [], "globals": [],
                "dangerous_globals": [], "executable": False, "truncated": False}
    raw = bytes(data)
    truncated = len(raw) >= MAX_SCAN_BYTES
    try:
        inner = _inner_pickle(raw)
    except Exception as e:
        return {"parsed": False, "reason": f"archive unreadable: {e}", "opcodes": [],
                "globals": [], "dangerous_globals": [], "executable": False,
                "truncated": truncated}
    if not inner:
        return {"parsed": False, "reason": "no pickle member found", "opcodes": [],
                "globals": [], "dangerous_globals": [], "executable": False,
                "truncated": truncated}

    ops: Set[str] = set()
    globals_found: Set[Tuple[str, str]] = set()
    pending: List[str] = []
    try:
        for op, arg, _pos in pickletools.genops(inner):
            ops.add(op.name)
            if op.name == "GLOBAL" and isinstance(arg, str):
                mod, _, nm = arg.partition(" ")
                globals_found.add((mod, nm))
            elif op.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE") and \
                    isinstance(arg, str):
                # STACK_GLOBAL takes its module and name off the stack as the two
                # preceding strings, so they are tracked rather than parsed from an
                # argument that does not exist.
                pending.append(arg)
                del pending[:-2]
            elif op.name == "STACK_GLOBAL" and len(pending) >= 2:
                globals_found.add((pending[-2], pending[-1]))
    except Exception as e:
        return {"parsed": False, "reason": f"opcode stream unreadable: {e}",
                "opcodes": sorted(ops), "globals": sorted(globals_found),
                "dangerous_globals": [], "executable": bool(ops & set(DANGEROUS_OPCODES)),
                "truncated": truncated}

    dangerous = sorted(f"{m}.{n}" for m, n in globals_found
                       if n in DANGEROUS_GLOBALS.get(m, ()))
    return {
        "parsed": True, "reason": "",
        "opcodes": sorted(ops),
        "globals": sorted(f"{m}.{n}" for m, n in globals_found),
        "dangerous_globals": dangerous,
        "executable": bool(ops & set(DANGEROUS_OPCODES)),
        "truncated": truncated,
    }


def verdict_for(scan: Optional[dict]) -> str:
    """MALICIOUS / EXECUTABLE / INERT / UNKNOWN.

    ``EXECUTABLE`` is deliberately not ``MALICIOUS``: almost every real PyTorch model
    contains ``REDUCE``, because that is how the format rebuilds a tensor. Reporting
    every model as malicious is how a scanner gets switched off. Only a global with no
    explainable reason to be in a serialized model earns the stronger word."""
    s = _d(scan)
    if not s.get("parsed"):
        return "UNKNOWN"
    if s.get("dangerous_globals"):
        return "MALICIOUS"
    return "EXECUTABLE" if s.get("executable") else "INERT"


def describe_source(source: Optional[dict], write_scope: str = "") -> str:
    """One line: where the artifact comes from and what that permits."""
    s = _d(source)
    uri = s.get("uri") or "an S3 location"
    bits = []
    if write_scope:
        bits.append(f"its bucket is writable by a {write_scope.replace('_', ' ')} "
                    f"principal, so whoever writes it executes code on the next deploy")
    if not s.get("pinned"):
        bits.append("the reference carries no ETag, so what loads is whatever sits at "
                    "that URI at deploy time")
    if not bits:
        return ""
    return f"Model artifact {uri} ({s.get('channel')}): " + "; and ".join(bits)
