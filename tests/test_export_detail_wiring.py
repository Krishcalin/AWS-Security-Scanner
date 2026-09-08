"""The detail catalogue must reach the exports built for other people's systems.

WHAT WAS WRONG. `aws_finding_detail` carries a risk/impact/steps write-up for every
one of the registered checks, and the HTML report and the JSON `finding_catalog`
render it. The two exports that leave the product for somebody else's console did
not: a SARIF rule was named `RDS-08`, described by whichever finding of that check
happened to come first in the run, and pointed at the repository root; an ASFF
finding arrived in Security Hub titled `RDS-08: RDS-08`. The best content in the
product was invisible exactly where a customer would read it.

WHY THE SUMMARY IS DERIVED, NOT AUTHORED. A title written here could describe a check
by something other than what it asserts, and would drift from the write-up the HTML
report shows for the same check. The first sentence of the catalogued `risk` prose is
existing, reviewed content and already summarises the condition, so it is taken
verbatim.

A SARIF RULE DESCRIBES A CHECK, NOT A RESOURCE. `fullDescription` previously held
`r.message` -- the message of the first finding of that check in that run -- so the
rule-level description varied with scan order and described one resource. That is the
second defect these tests pin.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import aws_finding_detail
from engine.aws_live_scanner import AWSLiveScanner
from test_live_scanner import make_scanner


def scan_with(rows):
    s = make_scanner(["IAM"])
    for status, cid, section, resource, message in rows:
        s._add(status, cid, section, resource, message)
    return s


def exports(scanner):
    tmp = tempfile.mkdtemp()
    sarif_path = os.path.join(tmp, "out.sarif")
    asff_path = os.path.join(tmp, "out.asff.json")
    scanner.save_sarif(sarif_path)
    scanner.save_asff(asff_path)
    with open(sarif_path, encoding="utf-8") as fh:
        sarif = json.load(fh)
    with open(asff_path, encoding="utf-8") as fh:
        asff = json.load(fh)
    return sarif, asff


@pytest.fixture()
def two_findings():
    return scan_with([
        ("FAIL", "RDS-02", "RDS", "prod-db", "DB PUBLICLY ACCESSIBLE | prod-db"),
        ("WARN", "RDS-08", "RDS", "prod-db", "IAM DB authentication=OFF | prod-db"),
    ])


# ── the summary is the catalogue's own sentence ─────────────────────────────

def test_the_summary_is_taken_verbatim_from_the_catalogue():
    """Not paraphrased and not composed here: the exports and the HTML report must
    say the same thing about the same check, or a reader comparing them finds two
    different descriptions of one finding."""
    risk = str(aws_finding_detail.get_detail("RDS-02")["risk"])
    summary = AWSLiveScanner._detail_summary("RDS-02")
    assert summary and risk.startswith(summary), summary


def test_the_summary_is_one_sentence_not_the_whole_write_up():
    """The write-ups run to paragraphs; a title field must not carry one."""
    risk = str(aws_finding_detail.get_detail("RDS-02")["risk"])
    summary = AWSLiveScanner._detail_summary("RDS-02")
    assert len(summary) < len(risk)
    assert summary.endswith((".", "!", "?")), summary


def test_a_check_with_no_write_up_yields_no_summary():
    """The fallback path matters more than the happy one: an uncatalogued id must
    return empty so the caller keeps the check id, rather than raising or inventing
    a description."""
    assert AWSLiveScanner._detail_summary("NO-SUCH-CHECK-99") == ""


def test_a_decimal_or_cidr_does_not_end_the_sentence():
    """`0.0.0.0/0` and `IMDSv1.` style text appear throughout these write-ups. A
    naive split on '.' would cut a summary mid-address and produce a title that reads
    as a different, wrong claim."""
    from engine.aws_live_scanner import _SENTENCE_END
    text = "Open to 0.0.0.0/0 on port 22. The second sentence."
    assert _SENTENCE_END.split(text, 1)[0] == "Open to 0.0.0.0/0 on port 22."


# ── SARIF ───────────────────────────────────────────────────────────────────

def test_sarif_rules_carry_the_write_up(two_findings):
    sarif, _ = exports(two_findings)
    rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert set(rules) == {"RDS-02", "RDS-08"}
    for cid, rule in rules.items():
        detail = aws_finding_detail.get_detail(cid)
        assert rule["shortDescription"]["text"].startswith(cid + ": ")
        assert rule["shortDescription"]["text"] != "%s: %s" % (cid, cid), (
            "shortDescription is still the check id twice")
        assert rule["fullDescription"]["text"] == str(detail["risk"]).strip()
        assert "help" in rule, "%s carries no help" % cid
        assert str(detail["impact"]).strip() in rule["help"]["text"]
        for step in detail["steps"]:
            assert str(step).strip() in rule["help"]["text"], step


def test_the_rule_description_does_not_depend_on_which_resource_came_first():
    """The defect this replaces: `fullDescription` was `r.message`, so the rule-level
    text described whichever resource the scan happened to reach first. Two runs of
    the same check over different resources must produce the same rule."""
    a = scan_with([("FAIL", "RDS-02", "RDS", "db-alpha", "alpha is public")])
    b = scan_with([("FAIL", "RDS-02", "RDS", "db-beta", "beta is public")])
    rule_a = exports(a)[0]["runs"][0]["tool"]["driver"]["rules"][0]
    rule_b = exports(b)[0]["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule_a == rule_b, "the rule changed with the resource"
    assert "alpha" not in json.dumps(rule_a)


def test_the_per_finding_message_still_reaches_the_sarif_result(two_findings):
    """Enriching the rule must not cost the detail that distinguishes one finding
    from another: the resource-specific message belongs on the result."""
    sarif, _ = exports(two_findings)
    messages = [x["message"]["text"] for x in sarif["runs"][0]["results"]]
    assert any("prod-db" in m for m in messages), messages


def test_sarif_short_description_stays_within_one_line(two_findings):
    """GitHub renders shortDescription as the alert title. Long write-ups are trimmed
    on a word boundary, and the untrimmed sentence stays available in fullDescription."""
    sarif, _ = exports(two_findings)
    for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
        text = rule["shortDescription"]["text"]
        assert len(text) <= 200, len(text)
        if text.endswith("..."):
            assert not text.endswith(" ..."), "trimmed mid-space: %r" % text


# ── ASFF ────────────────────────────────────────────────────────────────────

def test_asff_titles_name_the_condition(two_findings):
    _, asff = exports(two_findings)
    titles = {f["ProductFields"]["CheckId"]: f["Title"] for f in asff}
    for cid, title in titles.items():
        assert title != "%s: %s" % (cid, cid), "Security Hub still shows the id twice"
        assert title.startswith(cid + ": ")
        assert len(title) <= 256, len(title)


def test_asff_description_keeps_the_resource_message_and_adds_impact(two_findings):
    """Message first, because it is what makes this finding different from the next
    one for the same check; impact after, because Security Hub shows Description and
    the message alone never says why it matters."""
    _, asff = exports(two_findings)
    by_id = {f["ProductFields"]["CheckId"]: f for f in asff}
    desc = by_id["RDS-02"]["Description"]
    assert desc.startswith("DB PUBLICLY ACCESSIBLE | prod-db")
    assert "Impact:" in desc
    assert len(desc) <= 1024


def test_every_asff_finding_carries_remediation():
    """A finding with no Remediation block tells an operator what is wrong and
    nothing about the fix. Checks with no one-line CLI fall back to the catalogued
    steps, which exist for every registered check."""
    # EVERY ID HERE IS ALREADY PROVEN-FAILING ELSEWHERE, deliberately. These tests
    # synthesise findings through `_add` to exercise the exporters, and
    # `tests/conftest.py` records every `_add` call for docs/CHECK_FIRING.md -- so a
    # synthesised FAIL for a check that has never really failed would move it into
    # "proven to FAIL" without its logic ever running, quietly inflating the metric
    # the ratchet defends. An earlier draft of this test did exactly that to RDS-08.
    rows = [("FAIL", cid, "SEC", "res-%s" % cid, "%s fired" % cid)
            for cid in ("RDS-02", "IAM-04", "LOG-01", "IAMPE-01", "S3-01")]
    _, asff = exports(scan_with(rows))
    assert len(asff) == len(rows)
    for f in asff:
        text = f.get("Remediation", {}).get("Recommendation", {}).get("Text", "")
        assert text, "%s has no remediation" % f["ProductFields"]["CheckId"]
        assert len(text) <= 512, len(text)


def test_a_check_without_a_one_line_cli_falls_back_to_the_steps(monkeypatch):
    """Pins the fallback itself rather than trusting that some check happens to lack
    a CLI today: with REMEDIATION_MAP emptied, the steps must still get through."""
    import engine.aws_live_scanner as mod
    monkeypatch.setattr(mod, "REMEDIATION_MAP", {}, raising=True)
    _, asff = exports(scan_with(
        [("FAIL", "RDS-02", "RDS", "prod-db", "DB PUBLICLY ACCESSIBLE")]))
    text = asff[0]["Remediation"]["Recommendation"]["Text"]
    assert text.startswith("1) "), text
    first_step = str(aws_finding_detail.steps_for("RDS-02")[0]).strip()
    assert first_step[:60] in text
