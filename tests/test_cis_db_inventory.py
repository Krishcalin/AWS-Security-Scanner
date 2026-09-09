"""`docs/CIS_DATABASE_INVENTORY.md` is GENERATED, and has to stay that way.

The inventory is the left-hand column of the CIS Database mapping: what OverWatch already
asserts about the ten services the benchmark covers. It is the half that needs no source
document, and it exists so the mapping pass is a JOIN rather than a from-scratch
inventory written from somebody's recollection of the catalogue.

A generated table sitting next to a catalogue that moves is a table that quietly stops
being true — which is the entire reason `docs/CHECK_FIRING.md` has a staleness test. This
is that test for this file. Regenerate with:

    python scripts/cis_db_inventory.py
"""
from __future__ import annotations

import io
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_cis_db                                       # noqa: E402
from engine.aws_live_scanner import CHECK_SEVERITY as S             # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "CIS_DATABASE_INVENTORY.md")
GEN = os.path.join(ROOT, "scripts", "cis_db_inventory.py")


def test_the_generator_exists_and_the_doc_says_it_is_generated():
    assert os.path.exists(GEN), "the generator is gone; the doc is now hand-maintained"
    head = io.open(DOC, encoding="utf-8").read(400)
    assert "GENERATED" in head and "cis_db_inventory.py" in head, (
        "the doc must name its generator, or the next reader edits it by hand")


def test_the_doc_is_not_stale():
    """Regenerating must be a no-op. If this fails, run the generator and commit."""
    from scripts import cis_db_inventory                            # noqa: WPS433
    on_disk = io.open(DOC, encoding="utf-8", newline="").read()
    fresh = cis_db_inventory.build()
    assert on_disk.replace("\r\n", "\n") == fresh.replace("\r\n", "\n"), (
        "docs/CIS_DATABASE_INVENTORY.md is out of date with the catalogue — run "
        "`python scripts/cis_db_inventory.py` and commit the result")


def test_every_database_check_appears_in_the_inventory():
    """The point of the file. A check missing from it would be invisible during the
    mapping pass, and would then look like a gap the benchmark had found."""
    doc = io.open(DOC, encoding="utf-8").read()
    fams = {"AUR", "RDS", "DDB", "ELC", "MDB", "DOCDB", "KS", "NEP", "TS", "QLDB"}
    ids = sorted(c for c in S if c.rsplit("-", 1)[0] in fams)
    missing = [c for c in ids if f"`{c}`" not in doc]
    assert not missing, f"checks absent from the inventory: {missing}"
    assert ids, "the families are named wrongly — nothing matched"


def test_the_declines_are_reproduced_from_the_module_not_retyped():
    """Both decline dicts must appear, so the doc and the coverage tests cannot disagree
    about what is out of scope."""
    doc = io.open(DOC, encoding="utf-8").read()
    for key in list(aws_cis_db.NOT_DETERMINABLE) + list(
            aws_cis_db.DECLINED_AS_NOT_A_FINDING):
        assert key in doc, f"decline {key!r} is not carried into the inventory"


def test_the_doc_carries_no_benchmark_prose():
    """The handling rule, enforced rather than remembered. CIS benchmarks may not be
    redistributed: this file may cite section NUMBERS and recommendation COUNTS, which
    are references, and must not carry rationale, audit or remediation text."""
    doc = io.open(DOC, encoding="utf-8").read()
    assert "may not be redistributed" in doc, (
        "the doc must state its own handling rule, so a future editor sees it")
    for lifted in ("Rationale:", "Audit:", "Remediation:", "Impact:", "Default Value:"):
        assert lifted not in doc, (
            f"{lifted!r} is a CIS benchmark section heading — this file must not carry "
            f"the document's own prose, only references to it")


def test_the_generator_runs_clean():
    """It is run by hand, so it has to keep working when nobody has run it for a while."""
    r = subprocess.run([sys.executable, GEN], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, f"generator failed: {r.stderr[-800:]}"
