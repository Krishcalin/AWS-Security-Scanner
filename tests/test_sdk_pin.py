"""The boto3/botocore pin: the two must move together, and match what is installed.

WHY THIS EXISTS. The CHANGELOG records `botocore==1.43.51` breaking the offline build
once, because `boto3==1.40.51` caps `botocore<1.41.0`. Bumping one SDK without the other
produces a requirements file that cannot resolve — and it fails at *install* time, on a
connected host building the air-gapped wheelhouse, which is the worst place to find out.

The second failure is quieter and was live until this change: the pin said **1.40.51**
while the development environment had **1.43.51**. Every service model consulted while
authoring checks — including the whole 426-service gap analysis behind four coverage
batches — was read from 1.43.51, three minor versions ahead of what a fresh install
would get. Nothing compared the two, so nothing said so.

Both are cheap to check and neither was checked.
"""
from __future__ import annotations

import io
import os
import re
import sys

import pytest

from _layout import iter_modules

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = ("requirements.txt", "requirements-core.txt")
PIN = re.compile(r"^(boto3|botocore)==([0-9]+\.[0-9]+\.[0-9]+)\s*$", re.M)


def _pins(filename) -> dict:
    src = io.open(os.path.join(ROOT, filename), encoding="utf-8").read()
    return {m.group(1): m.group(2) for m in PIN.finditer(src)}


@pytest.mark.parametrize("filename", FILES)
def test_both_sdks_are_pinned(filename):
    p = _pins(filename)
    assert set(p) == {"boto3", "botocore"}, f"{filename} pins {sorted(p)}"


@pytest.mark.parametrize("filename", FILES)
def test_the_two_pins_are_the_same_version(filename):
    """boto3 X.Y.Z requires botocore>=X.Y.Z,<X.(Y+1).0, so a mismatched pair either
    fails to resolve or silently resolves botocore somewhere the models were never
    checked against. Moving them together is the only safe edit."""
    p = _pins(filename)
    assert p["boto3"] == p["botocore"], (
        f"{filename}: boto3=={p['boto3']} but botocore=={p['botocore']}. Bumping one "
        f"without the other is what broke the offline build before -- boto3 caps the "
        f"botocore minor it will accept.")


def test_the_two_requirements_files_agree():
    a, b = (_pins(f) for f in FILES)
    assert a == b, f"{FILES[0]} pins {a}, {FILES[1]} pins {b}"


def test_the_installed_botocore_matches_the_pin():
    """The drift this test was written for. Checks are authored by reading botocore's
    service models; if the installed version is not the pinned one, they are verified
    against a model the shipped product does not have."""
    import botocore
    pinned = _pins("requirements-core.txt")["botocore"]
    assert botocore.__version__ == pinned, (
        f"installed botocore {botocore.__version__} != pinned {pinned}. Service models "
        f"are the source of truth for every check in this codebase, so authoring against "
        f"a version the product does not ship is how a check ends up reading a field "
        f"nobody returns.")


def test_the_pin_is_recent_enough_for_the_agentcore_registry():
    """1.43.51 is the version that introduced ListingMode and the AgentCore Registry.
    Pinned below it, those are unreadable rather than absent -- and unreadable coverage
    that reads as absent is the failure mode this codebase guards against everywhere."""
    pinned = _pins("requirements-core.txt")["botocore"]
    major, minor, patch = (int(x) for x in pinned.split("."))
    assert (major, minor, patch) >= (1, 43, 51), (
        f"botocore {pinned} predates ListingMode and the AgentCore Registry")


def test_the_registry_and_listing_mode_are_actually_readable_now():
    """The point of the bump, asserted against the installed models rather than assumed
    from a version number."""
    import glob
    import gzip
    import json

    import botocore
    base = os.path.join(os.path.dirname(botocore.__file__), "data",
                        "bedrock-agentcore-control")
    versions = sorted(v for v in os.listdir(base)
                      if os.path.isdir(os.path.join(base, v)))
    f = glob.glob(os.path.join(base, versions[-1], "service-2.json*"))[0]
    op = gzip.open if f.endswith(".gz") else open
    with op(f, "rt", encoding="utf-8") as fh:
        model = json.load(fh)
    assert "ListRegistries" in model["operations"], "AgentCore Registry still absent"
    assert "ListingMode" in model["shapes"], "ListingMode still absent"


def test_no_module_still_claims_the_old_pin_is_current():
    """Several modules name the pinned version in their docstring as the thing they were
    verified against. A stale one is a claim about provenance that is no longer true."""
    stale = []
    # Without a floor the sweep reports "no stale pins" when it read no files
    # at all -- indistinguishable, in the suite output, from having checked them.
    mods = [(n, s) for n, s in iter_modules() if n.startswith("aws_")]
    assert len(mods) >= 50, (
        "only %d aws_ modules found across the layers -- the sweep is broken, "
        "not clean" % len(mods))
    for name, src in mods:
        for line in src.split("\n"):
            if "1.40.51" in line and ("pins" in line or "pinned" in line
                                      or "Taken from" in line or "read off" in line):
                stale.append(f"{name}: {line.strip()[:90]}")
    assert not stale, "modules still describing 1.40.51 as the current pin:\n" + \
        "\n".join(stale)
