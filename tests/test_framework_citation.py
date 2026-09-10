"""Compliance citations must name the document, and every framework must be known.

WHY. A finding carries `{"CIS": "2.3.2"}` and the exports rendered it as "CIS 2.3.2".
That number is only meaningful once you know which CIS document and which edition
indexes it -- "2.3" is an RDS control in the AWS Foundations Benchmark and "Ensure Tag
Policies are Enabled" in the AWS Compute Services Benchmark. The framework registry
has carried the name and version all along (`CIS` -> "CIS AWS Foundations Benchmark"
v3.0); the exports simply never asked for it, so an auditor reading a Security Hub
finding had a number they could not look up.

THE FORWARD-LOOKING HALF is `test_every_cited_framework_is_registered_and_native`.
Adding a second CIS benchmark is exactly the change that would make bare numbers
ambiguous, and that test fails the moment a check cites a framework id the registry
does not define -- so the identity has to exist before the citation can.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import compliance_crosswalk as cc
from engine.aws_live_scanner import COMPLIANCE_MAP


def registry():
    _crosswalk, frameworks, _digest = cc.get_crosswalk()
    return frameworks


# ── the citation itself ─────────────────────────────────────────────────────

def test_a_citation_names_the_document_and_edition():
    """The EDITION is half the citation, and this test is the reason that matters.

    It read `v3.0/1.5` for as long as the registry said v3.0, and it was correct then.
    v7.0.0 renumbers every section — 1.5 is root MFA in v3.0 and does not exist at all in
    v7.0.0, where section 1 is the Introduction — so a citation that named only the
    control would have gone from right to wrong with nothing failing anywhere. Naming the
    document and its edition is what makes a stale mapping visible instead of plausible.
    """
    assert (cc.framework_citation("CIS", "2.5")
            == "CIS AWS Foundations Benchmark v7.0.0/2.5")


def test_an_edition_already_in_the_name_is_not_repeated():
    """Caught in review of real output: NIST's name ends "Rev 5" and its version IS
    "Rev 5", so a naive name + ' v' + version rendered "NIST SP 800-53 Rev 5 vRev 5".
    The edition is suppressed when the name already carries it, and "v" is only
    prefixed to a numeric edition."""
    out = cc.framework_citation("NIST", "SC-7")
    assert out == "NIST SP 800-53 Rev 5/SC-7", out
    assert "vRev" not in out


def test_every_native_framework_renders_without_a_malformed_edition():
    fws = registry()
    for fid in sorted(cc._NATIVE_IDS):
        cite = cc.framework_citation(fid, "X.Y")
        head = cite.rsplit("/", 1)[0]
        assert cite.endswith("/X.Y"), cite
        assert " v v" not in head and "vRev" not in head, cite
        assert head.strip() == head and "  " not in head, cite


def test_an_unknown_framework_degrades_to_the_bare_pair():
    """The exports must not raise or emit a half-formed citation for an id the
    registry does not carry."""
    assert cc.framework_citation("NOPE", "9.9") == "NOPE 9.9"


def test_an_unreadable_registry_degrades_to_todays_string():
    """This module promises a missing or corrupt reference file leaves the native
    pipeline unaffected. Citations therefore fall back to exactly what the exports
    emitted before this change, rather than failing the export."""
    assert cc.framework_citation("CIS", "1.5", frameworks={}) == "CIS 1.5"


@pytest.mark.parametrize("fid,ctrl", [("", "1.5"), ("CIS", ""), ("", "")])
def test_blank_input_never_produces_a_dangling_separator(fid, ctrl):
    out = cc.framework_citation(fid, ctrl)
    assert "/" not in out and not out.startswith(" ") and not out.endswith(" ")


# ── the wiring: what a consumer actually receives ───────────────────────────

def exported(check_id="RDS-02"):
    import json
    import tempfile
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from test_live_scanner import make_scanner

    s = make_scanner(["IAM"])
    s._add("FAIL", check_id, "RDS", "prod-db", "DB PUBLICLY ACCESSIBLE | prod-db")
    tmp = tempfile.mkdtemp()
    s.save_asff(os.path.join(tmp, "a.json"))
    s.save_sarif(os.path.join(tmp, "a.sarif"))
    with open(os.path.join(tmp, "a.json"), encoding="utf-8") as fh:
        asff = json.load(fh)
    with open(os.path.join(tmp, "a.sarif"), encoding="utf-8") as fh:
        sarif = json.load(fh)
    return asff, sarif


def test_asff_related_requirements_name_the_document():
    """Security Hub shows RelatedRequirements to an auditor. "CIS 2.3.2" sends them
    to the wrong document as easily as the right one."""
    asff, _ = exported()
    related = asff[0]["Compliance"]["RelatedRequirements"]
    assert "CIS AWS Foundations Benchmark v7.0.0/3.2.3" in related, related
    assert "CIS 3.2.3" not in related, related
    # RDS-02 carries BOTH benchmarks, and the two numbers are unrelated: Foundations
    # 3.2.3 and Database 3.12. Rendering either as a bare "CIS 3.x" would make them
    # look like the same control seen twice.
    assert "CIS AWS Database Services Benchmark v2.0.0/3.12" in related, related


def test_sarif_help_carries_citations_but_tags_stay_machine_stable():
    """Tags are what consumers filter on, so they keep their short, stable form;
    the qualified citation goes in the help a person reads."""
    _, sarif = exported()
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "CIS:3.2.3" in rule["properties"]["tags"], rule["properties"]["tags"]
    assert "CIS AWS Foundations Benchmark v7.0.0/3.2.3" in rule["help"]["text"]
    assert "**Compliance:**" in rule["help"]["markdown"]


# ── the registry integrity guard (what makes Phase 1 unambiguous) ───────────

def test_every_cited_framework_is_registered_and_native():
    """Every framework a check cites must exist in the registry AND be flagged
    native. Native means hand-tagged per check; a cited framework that is not
    registered has no name or edition to cite, and one that is not native would be
    claiming derived coverage as if it were hand-tagged.

    This is the guard that keeps a second CIS benchmark honest: tagging checks with
    a new id fails here until that id is registered with its own name and version,
    at which point its citations are automatically distinguishable from Foundations'."""
    fws = registry()
    cited = set()
    for mapping in COMPLIANCE_MAP.values():
        cited.update(mapping or {})

    unregistered = sorted(c for c in cited if c not in fws)
    assert not unregistered, (
        "checks cite framework(s) with no registry entry: %s — register the "
        "framework (id, name, version) before citing it, or the export emits a "
        "control number nobody can resolve" % unregistered)

    not_native = sorted(c for c in cited if not fws[c].get("native"))
    assert not not_native, (
        "checks hand-tag framework(s) not flagged native: %s" % not_native)


def test_the_native_set_is_declared_in_both_the_code_and_the_data():
    """`_NATIVE_IDS` was a dead constant: the edge rule enforces each framework's
    `native` flag from the data file, and nothing ever read the code's copy, so the
    two could drift in silence. The drift is dangerous in one direction — a framework
    that loses its native flag becomes a legal crosswalk target, and its coverage
    quietly turns derived while the module docstring still promises it is hand-tagged.

    The check lives here rather than in the loader deliberately: `load_crosswalk` is a
    pure function over ANY document, and fixtures and customer overlays legitimately
    declare only some natives. An equality check inside it rejected them — it broke
    eight existing crosswalk tests before this was moved out. The repository's own
    registry is the only document the equality is true of, so the repository's tests
    are where it belongs."""
    fws = registry()
    from_data = frozenset(f for f, m in fws.items() if m.get("native"))
    assert from_data == cc._NATIVE_IDS, (
        "native set drift: registry declares %s, code declares %s"
        % (sorted(from_data), sorted(cc._NATIVE_IDS)))


def test_a_native_framework_is_never_a_crosswalk_target():
    """The other half of the same fact, and the reason the flag matters: derived
    coverage must never reach a hand-tagged framework, or a check's compliance claim
    would be part asserted and part inferred with no way to tell them apart."""
    crosswalk, fws, _digest = cc.get_crosswalk()
    natives = {f for f, m in fws.items() if m.get("native")}
    leaked = sorted({fid for edges in crosswalk.values() for fid in edges}
                    & natives)
    assert not leaked, "crosswalk edges target native framework(s): %s" % leaked
