"""One finding, four exports, one remediation.

THE DEFECT. `_add` fills `Result.remediation` from `REMEDIATION_MAP` only when the
status is FAIL, so a WARN finding reached every export with an empty string. The four
output paths then each did something different with that:

  * `_build_finding_catalog` (the HTML report's per-check cards) looked the text up by
    check id and showed the real, specific remediation;
  * `save_json` emitted an empty string;
  * `save_sarif` emitted an empty string;
  * `save_asff` substituted the literal "Review and apply least privilege".

So one scan produced an HTML report telling an operator exactly how to fix something,
a JSON export saying nothing, and a Security Hub finding carrying invented generic
advice — in the export that feeds the customer's own security console, which is the
worst place of the four to be confidently vague. Two artefacts describing one scan and
disagreeing is the failure this codebase warns about repeatedly.

IT IS NOT A NARROW CASE. 82 checks in this catalogue only ever emit WARN
(`docs/CHECK_FIRING.md`), so their written remediation could never be shown by three
of the four exports, and many more checks warn conditionally.

THE CATALOGUE WAS THE ONE THAT WAS RIGHT, so everything resolves the way it does:
by check id, because a remediation is a property of the CHECK, not of how severely a
particular observation happened to land. Status still gates it — PASS and INFO get
nothing, since there is no fix to offer for a control that is in place.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.aws_live_scanner import REMEDIATION_MAP
from test_live_scanner import make_scanner

#: A real registered check with a real remediation, so the assertions are about
#: resolution and not about a fixture we invented.
WARN_CHECK = "S3-05"
FAIL_CHECK = "S3-01"
#: The PASS fixture MUST be a check that has a remediation in the map. S3-02 does not,
#: so the status gate was never exercised: dropping the gate entirely still returned an
#: empty string for it, and `test_a_passing_control_offers_no_remediation` passed
#: against a mutation that broke exactly what it is named for.
PASS_CHECK = "S3-03"


@pytest.fixture()
def scanner():
    s = make_scanner(["S3"])
    s.account = "123456789012"
    s._add("WARN", WARN_CHECK, "S3", "bucket-a", "a warning about bucket-a")
    s._add("FAIL", FAIL_CHECK, "S3", "bucket-b", "a failure about bucket-b")
    s._add("PASS", PASS_CHECK, "S3", "bucket-c", "bucket-c is fine")
    return s


def written(scanner, method):
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        getattr(scanner, method)(path)
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    finally:
        os.unlink(path)


def test_the_catalogue_has_a_remediation_for_the_fixture_checks():
    """Anchors everything below: if these were uncatalogued the tests would pass on
    two empty strings being equal. PASS_CHECK is included for the sharper reason —
    a PASS check with no remediation makes the status gate untestable, which is how
    the first version of this file shipped."""
    assert REMEDIATION_MAP.get(WARN_CHECK)
    assert REMEDIATION_MAP.get(FAIL_CHECK)
    assert REMEDIATION_MAP.get(PASS_CHECK), (
        "the PASS fixture has no remediation, so dropping the status gate would "
        "change nothing and the gate's test would defend nothing")


# ── the WARN case, which is the whole defect ───────────────────────────────

def test_json_carries_a_warns_real_remediation(scanner):
    rows = {r["check_id"]: r for r in written(scanner, "save_json")["results"]}
    assert rows[WARN_CHECK]["remediation_cmd"] == REMEDIATION_MAP[WARN_CHECK]


def test_sarif_carries_a_warns_real_remediation(scanner):
    doc = written(scanner, "save_sarif")
    results = doc["runs"][0]["results"]
    warn = [r for r in results if r["ruleId"] == WARN_CHECK]
    assert warn, "the WARN finding is absent from SARIF entirely"
    assert warn[0]["properties"]["remediation"] == REMEDIATION_MAP[WARN_CHECK]


def test_security_hub_gets_the_real_fix_not_generic_advice(scanner):
    """The worst of the four: invented boilerplate landing in the customer's own
    security console, beside an HTML report carrying the specific fix."""
    findings = written(scanner, "save_asff")
    warn = [f for f in findings if f["ProductFields"]["CheckId"] == WARN_CHECK]
    assert warn, "the WARN finding is absent from ASFF entirely"
    text = warn[0]["Remediation"]["Recommendation"]["Text"]
    assert text == REMEDIATION_MAP[WARN_CHECK][:512]
    assert "Review and apply least privilege" not in text


# ── the four paths must agree ──────────────────────────────────────────────

def test_every_export_says_the_same_thing_about_one_finding(scanner):
    """The anti-drift assertion. Four call sites resolved this four ways for as long
    as they have existed; nothing compared them, so nothing objected."""
    catalogue = {e["check_id"]: e["remediation_cmd"]
                 for e in scanner._build_finding_catalog()}
    js = {r["check_id"]: r["remediation_cmd"]
          for r in written(scanner, "save_json")["results"]}
    sarif = {r["ruleId"]: r["properties"]["remediation"]
             for r in written(scanner, "save_sarif")["runs"][0]["results"]}
    asff = {f["ProductFields"]["CheckId"]:
            f.get("Remediation", {}).get("Recommendation", {}).get("Text", "")
            for f in written(scanner, "save_asff")}

    for check in (WARN_CHECK, FAIL_CHECK):
        expected = REMEDIATION_MAP[check]
        assert catalogue[check] == expected, "catalogue disagrees"
        assert js[check] == expected, "save_json disagrees"
        assert sarif[check] == expected, "save_sarif disagrees"
        assert asff[check] == expected[:512], "save_asff disagrees"


def test_a_failure_still_resolves_as_it_always_did(scanner):
    """The regression guard: FAIL was already correct everywhere, and narrowing the
    rule to fix WARN must not have moved it."""
    rows = {r["check_id"]: r for r in written(scanner, "save_json")["results"]}
    assert rows[FAIL_CHECK]["remediation_cmd"] == REMEDIATION_MAP[FAIL_CHECK]


# ── and good news must not carry a fix ─────────────────────────────────────

def test_a_passing_control_offers_no_remediation(scanner):
    """save_json carries every status, so without the status gate a PASS would arrive
    with instructions for fixing something that is not broken."""
    rows = {r["check_id"]: r for r in written(scanner, "save_json")["results"]}
    assert rows[PASS_CHECK]["status"] == "PASS"
    assert rows[PASS_CHECK]["remediation_cmd"] == "", (
        "a passing control was given instructions for fixing something that is not "
        "broken")


def test_asff_omits_remediation_rather_than_inventing_one():
    """An id the catalogue does not know — CWPP-04 and CIEM-01 are real examples that
    WARN — used to receive "Review and apply least privilege", which for a
    missing-vuln-database warning is not vague but wrong. ASFF makes Remediation
    optional; saying nothing is the honest answer."""
    s = make_scanner(["S3"])
    s.account = "123456789012"
    s._add("WARN", "ZZZ-99", "S3", "res", "an id the catalogue does not know")
    findings = written(s, "save_asff")
    assert findings, "the finding vanished from ASFF"
    assert "Remediation" not in findings[0], (
        "an uncatalogued finding was given invented remediation text: %r"
        % findings[0].get("Remediation"))
