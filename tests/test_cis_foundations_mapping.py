"""The CIS AWS Foundations v7.0.0 mapping, and the properties that make it worth quoting.

A 70-row compliance mapping over the benchmark this product is built around is the sort of
artefact that ends up in front of an auditor, which is exactly why it must not be a
hand-typed table sitting next to a catalogue that moves. The mapping is data
(`engine/aws_cis_foundations_map.py`), the document is rendered from it
(`scripts/cis_foundations_benchmark.py`), and these tests assert the things that would
otherwise rot silently:

  * every recommendation 2.1.1 … 6.8 appears exactly once, with no gaps and no inventions;
  * every check id named in the mapping actually exists in the catalogue;
  * the `CIS` keys in COMPLIANCE_MAP agree with the mapping in BOTH directions;
  * no check is presented as covering something it cannot FAIL on;
  * no `1.x` citation survives anywhere, because section 1 of v7.0.0 has no recommendations;
  * the document carries no benchmark prose, which is a licence condition and not a style
    preference.

The last three are the ones that keep it honest rather than merely consistent.
"""
from __future__ import annotations

import io
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_cis_foundations as FDN                          # noqa: E402
from engine import aws_cis_foundations_map as M                        # noqa: E402
from engine import compliance_crosswalk as cc                          # noqa: E402
from engine.aws_live_scanner import CHECK_SEVERITY as S                # noqa: E402
from engine.aws_live_scanner import COMPLIANCE_MAP as C                # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "CIS_FOUNDATIONS_BENCHMARK.md")
GEN = os.path.join(ROOT, "scripts", "cis_foundations_benchmark.py")


# ═════════════════════════════════════════════════════════════════════════════════
# the mapping is complete and references only real things
# ═════════════════════════════════════════════════════════════════════════════════
def test_every_recommendation_is_present_exactly_once():
    """70 rows. A missing one would read as a control nobody considered; an extra one
    would be a control that does not exist."""
    assert len(M.RECOMMENDATIONS) == 70
    for num, name, count in M.SECTIONS:
        got = sum(1 for r in M.RECOMMENDATIONS if r.split(".", 1)[0] == num)
        assert got == count, f"section {num} ({name}) should hold {count}, holds {got}"


def test_the_section_counts_sum_to_the_benchmark_total():
    assert sum(c for _n, _l, c in M.SECTIONS) == 70


def test_there_is_no_section_one():
    """THE FACT THAT INVALIDATED EVERY PRE-EXISTING CITATION. v7.0.0 made section 1 the
    Introduction, so a `1.x` recommendation number does not exist in this edition at all.
    Every one of the 124 `CIS` keys this product shipped before the move was a `1.x`,
    `2.x`, `3.x`, `4.x` or `5.x` against a document where those now mean something else.
    """
    assert not [r for r in M.RECOMMENDATIONS if r.startswith("1.")]
    assert not [n for n, _l, _c in M.SECTIONS if n == "1"]


def test_every_subsection_is_numbered_from_one_without_gaps():
    from collections import defaultdict
    kids = defaultdict(list)
    for r in M.RECOMMENDATIONS:
        parent = r.rsplit(".", 1)[0]
        kids[parent].append(int(r.rsplit(".", 1)[1]))
    for parent, got in kids.items():
        got.sort()
        assert got == list(range(min(got), min(got) + len(got))), (
            f"{parent}.x is not contiguous: {got}")


def test_every_check_named_in_the_mapping_exists():
    """The failure this prevents: a check is renamed, the mapping keeps citing the old id,
    and the document goes on claiming coverage that nothing provides."""
    named = {c for row in M.RECOMMENDATIONS.values() for c in row[3]}
    missing = sorted(c for c in named if c not in S)
    assert not missing, f"mapping cites checks that do not exist: {missing}"


def test_every_verdict_and_profile_is_one_of_the_declared_ones():
    bad = {r: v[2] for r, v in M.RECOMMENDATIONS.items() if v[2] not in M.VERDICTS}
    assert not bad, f"unknown verdicts: {bad}"
    badp = {r: v[1] for r, v in M.RECOMMENDATIONS.items()
            if v[1] not in (M.AUTOMATED, M.MANUAL)}
    assert not badp, f"unknown profiles: {badp}"


# ═════════════════════════════════════════════════════════════════════════════════
# the mapping and the compliance map agree — in both directions
# ═════════════════════════════════════════════════════════════════════════════════
def test_every_cis_key_matches_the_mapping():
    """Forward direction: a key in COMPLIANCE_MAP must be the home the mapping computes."""
    keyed = {c: v["CIS"] for c, v in C.items() if "CIS" in v}
    assert keyed, "no CIS keys are registered at all"
    wrong = {c: (v, M.recommendation_for(c)) for c, v in keyed.items()
             if v != M.recommendation_for(c)}
    assert not wrong, f"COMPLIANCE_MAP disagrees with the mapping (got, expected): {wrong}"


def test_every_check_with_a_home_carries_the_key():
    """Reverse direction, and the one that actually rots. A check added to the mapping
    without its compliance key would be described as covering a recommendation while
    reporting no CIS citation on the finding itself."""
    expect = {c for c in S if M.recommendation_for(c)}
    keyed = {c for c, v in C.items() if "CIS" in v}
    assert not (expect - keyed), f"mapped but not keyed: {sorted(expect - keyed)}"
    assert not (keyed - expect), f"keyed but not mapped: {sorted(keyed - expect)}"


def test_every_cited_number_is_a_recommendation_that_exists():
    """A citation to a number the document does not carry is unresolvable, and looks
    exactly like one that resolves."""
    bad = {c: v["CIS"] for c, v in C.items()
           if "CIS" in v and v["CIS"] not in M.RECOMMENDATIONS}
    assert not bad, f"citations to non-existent recommendations: {bad}"


def test_no_check_is_homed_on_a_row_it_does_not_appear_on():
    for check, rec in M._homes().items():
        assert check in M.RECOMMENDATIONS[rec][3], (
            f"{check} is homed at {rec}, which does not name it")


def test_a_shared_check_is_counted_once():
    """2.9, 4.9 and 6.4 are decided by the same call as their neighbour, and are marked
    `elsewhere` for that reason. If one became a home, IAM-05, LOG-08 or VPC-01 would
    appear to provide two independent coverages from one API read."""
    shared = [r for r, v in M.RECOMMENDATIONS.items() if v[2] == M.ELSEWHERE]
    assert shared, "no shared rows at all — did the verdict lose its meaning?"
    homes = set(M._homes().values())
    for rec in shared:
        assert rec not in homes, f"{rec} is marked elsewhere but owns a check"


# ═════════════════════════════════════════════════════════════════════════════════
# honesty
# ═════════════════════════════════════════════════════════════════════════════════
def test_covered_means_a_check_is_named():
    empty = sorted(r for r, v in M.RECOMMENDATIONS.items()
                   if v[2] in (M.COVERED, M.NARROWED, M.PARTIAL, M.ELSEWHERE) and not v[3])
    assert not empty, f"claimed as covered/observed with no check named: {empty}"


def test_nothing_is_covered_by_a_check_that_cannot_fail():
    """THE POINT OF THE PARTIAL VERDICT. RDS-03's Multi-AZ arm reads its setting and emits
    PASS or WARN and never FAIL. A check that cannot fail can tell you a value; it can
    never tell an operator they are non-compliant, so presenting one as `covered` would
    overstate the catalogue in the one document most likely to be quoted back at us."""
    assert M.verdict_for("3.2.4") == M.PARTIAL
    assert M.recommendation_for("RDS-03") == "3.2.2", (
        "RDS-03 must be keyed to the control it can actually fail on")


def test_a_narrowed_row_says_what_it_does_not_decide():
    """`narrowed` is a claim about a limit, so the limit has to be written down. A row
    that says 'narrowed' with no explanation is a shortfall wearing a decision's clothes.
    """
    narrowed = [r for r, v in M.RECOMMENDATIONS.items() if v[2] == M.NARROWED]
    assert narrowed, "no narrowed rows — did the verdict lose its contents?"
    for rec in narrowed:
        note = M.RECOMMENDATIONS[rec][4]
        assert len(note) > 60, f"{rec} is narrowed with no account of what it omits"


def test_the_gaps_are_named_rather_than_rounded_away():
    """There are none, and that is worth asserting rather than assuming: if a future
    recommendation is added with no check, this fails until the row explains itself."""
    for rec in [r for r, v in M.RECOMMENDATIONS.items() if v[2] == M.NO_CHECK]:
        assert len(M.RECOMMENDATIONS[rec][4]) > 15, (
            f"{rec} is recorded as a gap without saying what would close it")


def _resolved(cid: str, seen=None) -> str:
    """A register entry's reason, following an `as XXX-NN` cross-reference to its source.

    Entries legitimately say "as ATTACK-01" rather than repeating a paragraph six times.
    That is a reference, not an absence — but only if the entry it points at explains
    itself, so this resolves the chain and refuses to loop."""
    seen = seen or set()
    why = M.MISCITED[cid][1]
    ref = re.fullmatch(r"as ([A-Z][A-Z0-9]*-\d+)(?:,.*)?", why.strip())
    if ref and ref.group(1) not in seen and ref.group(1) in M.MISCITED:
        return _resolved(ref.group(1), seen | {cid})
    return why


def test_every_removed_citation_records_why():
    """A citation deleted with no reason is indistinguishable from one deleted by
    accident, and the next reader restores it."""
    for cid, (old, _why) in M.MISCITED.items():
        assert cid in S, f"MISCITED names {cid}, which is not a check"
        assert re.fullmatch(r"\d+(\.\d+){1,2}", old), f"{cid}: {old!r} is not a number"
        assert len(_resolved(cid)) > 25, (
            f"{cid} was un-cited with no reason worth reading")
    for cid, old in M.EKS_NUMBERED.items():
        assert cid in S, f"EKS_NUMBERED names {cid}, which is not a check"
        assert re.fullmatch(r"\d+(\.\d+){1,2}", old)


def test_every_cross_reference_in_the_register_resolves():
    """An `as NOPE-99` pointing at an entry that does not exist, or round in a circle,
    would be an explanation that reads as one without being one."""
    for cid, (_old, why) in M.MISCITED.items():
        ref = re.fullmatch(r"as ([A-Z][A-Z0-9]*-\d+)(?:,.*)?", why.strip())
        if ref:
            assert ref.group(1) in M.MISCITED, (
                f"{cid} refers to {ref.group(1)}, which is not in the register")
            assert len(_resolved(cid)) > 25, (
                f"{cid} refers to {ref.group(1)}, which explains nothing itself")


def test_a_repointed_citation_is_not_also_recorded_as_removed():
    """The two registers make opposite claims — one says the product no longer cites this
    control, the other says it cites a different one. A check in both would leave a reader
    reconciling an old report with no way to tell which happened."""
    both = sorted(set(M.REPOINTED) & set(M.MISCITED))
    assert not both, f"{both} are recorded as removed AND re-pointed"


def test_every_repointed_check_landed_where_the_register_says():
    """The register has to agree with the catalogue, or it is documentation of a change
    somebody meant to make."""
    for cid, (old, new, why) in M.REPOINTED.items():
        assert cid in S, f"REPOINTED names {cid}, which is not a check"
        assert new in M.RECOMMENDATIONS, f"{cid} points at {new}, which does not exist"
        assert C.get(cid, {}).get("CIS") == new, (
            f"{cid} is recorded as re-pointed to {new}, catalogue says "
            f"{C.get(cid, {}).get('CIS')!r}")
        assert M.RENUMBERED.get(old) != new, (
            f"{cid}: {old} -> {new} IS the plain renumber, so it does not belong in "
            f"REPOINTED — that register is for the ones the table gets wrong")
        assert len(why) > 40, f"{cid} was re-pointed with no reason worth reading"


def test_nothing_removed_still_carries_a_cis_key():
    stale = sorted(c for c in set(M.MISCITED) | set(M.EKS_NUMBERED)
                   if "CIS" in C.get(c, {}))
    assert not stale, (
        f"{stale} were recorded as mis-cited and still carry a CIS key — the register "
        f"and the catalogue disagree, which is worse than either being wrong alone")


def test_every_renumber_lands_on_a_real_recommendation():
    bad = {o: n for o, n in M.RENUMBERED.items() if n not in M.RECOMMENDATIONS}
    assert not bad, f"renumbering points at non-existent recommendations: {bad}"
    # and the table must not claim a move that is really a re-point: IAMPE-22 went from
    # 1.16 to 2.21, which is NOT where 1.16 went, so it belongs in MISCITED reasoning
    # rather than here.
    assert M.RENUMBERED["1.16"] == "2.14"


# ═════════════════════════════════════════════════════════════════════════════════
# the framework registry
# ═════════════════════════════════════════════════════════════════════════════════
def test_the_registry_declares_the_edition_the_citations_use():
    """A citation renders as `<name> v<version>/<control>`, so the registry is where the
    edition actually lives. If it still said v3.0 every export would name the wrong
    document while carrying the right numbers — the one failure a reader cannot detect."""
    _cw, fws, _d = cc.get_crosswalk()
    assert fws["CIS"]["version"] == "7.0.0", fws["CIS"]["version"]
    assert fws["CIS"]["catalog_size"] == len(M.RECOMMENDATIONS)
    assert cc.framework_citation("CIS", "2.1.1").endswith("v7.0.0/2.1.1")


def test_the_sibling_benchmarks_keep_their_own_keys():
    """Foundations 3.2.1 is RDS encryption, Compute 3.2 is an ECS control and Database 3.2
    is an RDS one. Three documents, three numbering schemes; folding them into one key
    would mis-cite every mapping in all three directions at once."""
    _cw, fws, _d = cc.get_crosswalk()
    for fid in ("CIS", "CIS-COMPUTE", "CIS-DB"):
        assert fws[fid]["native"], f"{fid} must stay hand-tagged"
    assert len({fws[f]["name"] for f in ("CIS", "CIS-COMPUTE", "CIS-DB")}) == 3


# ═════════════════════════════════════════════════════════════════════════════════
# the generated document
# ═════════════════════════════════════════════════════════════════════════════════
def _doc() -> str:
    return io.open(DOC, encoding="utf-8").read()


def test_the_generator_runs_clean():
    """It is run by hand, so it has to keep working when nobody has run it for a while."""
    r = subprocess.run([sys.executable, GEN], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, f"generator failed: {r.stderr[-900:]}"


def test_the_document_is_current():
    from scripts.cis_foundations_benchmark import build            # noqa: WPS433
    assert _doc() == build(), (
        "docs/CIS_FOUNDATIONS_BENCHMARK.md is stale — run "
        "`python scripts/cis_foundations_benchmark.py`")


def test_the_document_carries_no_benchmark_prose():
    """THE HANDLING RULE, ENFORCED RATHER THAN REMEMBERED.

    CIS Benchmarks may not be redistributed, and the document's own terms state it is
    never acceptable to host one in any format on a non-CIS site. This file may cite
    recommendation NUMBERS and COUNTS, which are references, and must not carry the
    benchmark's rationale, audit, impact or remediation text — nor its recommendation
    titles, which is why every label in the mapping is written from the AWS behaviour
    instead."""
    doc = _doc()
    assert "may not be redistributed" in doc, (
        "the document must state its own handling rule, so a future editor sees it")
    for lifted in ("Rationale:", "Audit:", "Remediation:", "Impact:", "Default Value:",
                   "Profile Applicability:", "CIS Controls:"):
        assert lifted not in doc, (
            f"{lifted!r} is a CIS benchmark section heading — this file must not carry "
            f"the document's own prose, only references to it")


def test_no_benchmark_title_is_reproduced_as_a_label():
    """The labels are this project's own descriptions, and the tell for a lifted title is
    that CIS writes almost every one of them as an imperative starting `Ensure`."""
    lifted = sorted(r for r, v in M.RECOMMENDATIONS.items()
                    if v[0].startswith(("Ensure ", "Eliminate ", "Maintain ")))
    assert not lifted, (
        f"{lifted} read like the benchmark's own titles rather than a description "
        f"written from the AWS behaviour")


def test_the_pdf_is_not_in_the_repository():
    """The rule that is easiest to break by accident, and the only one with a licence
    behind it. A benchmark PDF committed for convenience is a redistribution."""
    hits = []
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs
                   if d not in (".git", "node_modules", "__pycache__", ".venv")]
        for f in files:
            low = f.lower()
            if low.endswith((".pdf", ".epub")) and "cis" in low and "benchmark" in low:
                hits.append(os.path.join(base, f))
    assert not hits, f"CIS benchmark document(s) in the repository: {hits}"


def test_the_document_names_every_check_it_claims():
    """The rendered table is the artefact people read. If a check id in it does not exist,
    the document is claiming coverage the product does not have."""
    doc = _doc()
    for cid in {c for row in M.RECOMMENDATIONS.values() for c in row[3]}:
        assert f"**{cid}**" in doc, f"{cid} is mapped but absent from the document"
