"""Tests for the detailed finding write-ups (aws_finding_detail) and their rendering into
the JSON (finding_catalog) + HTML (detailed cards, light theme) reports."""
import json
import os
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_finding_detail as D
from test_live_scanner import make_scanner
import aws_live_scanner as A


# ── module coverage + shape ───────────────────────────────────────────────────
def test_every_actionable_check_has_detail():
    # every check with a one-line remediation (i.e. every FAIL-able check) has a full write-up
    missing = [c for c in A.REMEDIATION_MAP if c not in D.FINDING_DETAIL]
    assert missing == [], f"checks missing detail: {missing}"


def test_every_detail_is_well_formed():
    for cid, d in D.FINDING_DETAIL.items():
        assert isinstance(d.get("risk"), str) and len(d["risk"]) > 40, cid
        assert isinstance(d.get("impact"), str) and len(d["impact"]) > 15, cid
        assert isinstance(d.get("steps"), list) and len(d["steps"]) >= 3, cid
        assert all(isinstance(s, str) and s.strip() for s in d["steps"]), cid


def test_detail_content_is_unescaped_not_html_entities():
    # the authoring pass HTML-escaped some CLI; the module must hold RAW text so the HTML
    # renderer escapes exactly once (no &lt; / &gt; double-escape).
    for cid, d in D.FINDING_DETAIL.items():
        blob = d["risk"] + d["impact"] + " ".join(d["steps"])
        assert "&lt;" not in blob and "&gt;" not in blob, cid


def test_get_detail_lookup():
    assert D.get_detail("DSPM-02") is not None
    assert D.get_detail("NOPE-99") is None
    assert D.steps_for("IAM-01") and D.steps_for("NOPE-99") == []


# ── finding_catalog builder ───────────────────────────────────────────────────
def _scanner_with(findings):
    s = make_scanner(sections=["IAM"])
    s.account = "123456789012"
    for st, cid, sec, res, msg in findings:
        s._add(st, cid, sec, res, msg)
    return s


def test_catalog_dedups_and_counts():
    s = _scanner_with([("FAIL", "DSPM-02", "DATA", "db1", "x"),
                       ("FAIL", "DSPM-02", "DATA", "db2", "y"),
                       ("PASS", "KMS-01", "KMS", "all", "ok")])
    cat = s._build_finding_catalog()
    ids = [e["check_id"] for e in cat]
    assert ids == ["DSPM-02"]                 # deduped; PASS excluded
    e = cat[0]
    assert e["count"] == 2 and set(e["affected"]) == {"db1", "db2"}
    assert e["risk"] and len(e["steps"]) >= 3 and "SC-7" in str(e["compliance"])


def test_catalog_is_severity_ranked():
    s = _scanner_with([("FAIL", "DSPM-01", "DATA", "a", "med"),      # MEDIUM
                       ("FAIL", "IAM-01", "IAM", "root", "crit"),    # CRITICAL
                       ("FAIL", "DSPM-02", "DATA", "b", "high")])    # HIGH
    order = [e["check_id"] for e in s._build_finding_catalog()]
    assert order == ["IAM-01", "DSPM-02", "DSPM-01"]   # CRITICAL, HIGH, MEDIUM


def test_catalog_only_fail_and_warn():
    s = _scanner_with([("WARN", "EXPOSURE-02", "EXPOSURE", "r", "w"),
                       ("INFO", "PATHS-01", "CORRELATE", "s", "i"),
                       ("PASS", "IAM-03", "IAM", "root", "p")])
    ids = [e["check_id"] for e in s._build_finding_catalog()]
    assert ids == ["EXPOSURE-02"]             # WARN kept; INFO/PASS dropped


# ── JSON + HTML rendering ─────────────────────────────────────────────────────
def _render(findings):
    s = _scanner_with(findings)
    jp = tempfile.mktemp(suffix=".json")
    hp = tempfile.mktemp(suffix=".html")
    with patch("builtins.print"):
        s.save_json(jp)
        s.save_html(hp)
    data = json.load(open(jp, encoding="utf-8"))
    html = open(hp, encoding="utf-8").read()
    os.unlink(jp); os.unlink(hp)
    return data, html


def test_json_includes_finding_catalog_with_detail():
    data, _ = _render([("FAIL", "DSPM-02", "DATA", "customers-db", "public RDS")])
    assert "finding_catalog" in data
    e = data["finding_catalog"][0]
    assert e["check_id"] == "DSPM-02" and e["risk"] and len(e["steps"]) >= 3
    assert e["severity"] == "HIGH" and e["compliance"]


def test_html_is_light_and_detailed():
    _, html = _render([("FAIL", "IAM-01", "IAM", "root", "root MFA off"),
                       ("FAIL", "DSPM-02", "DATA", "customers-db", "public RDS")])
    assert "#eef3fb" in html and "#0d1117" not in html            # light, not the old dark
    assert "Business impact" in html and "step by step" in html   # detailed cards
    assert "flbl risk" in html and "fcard" in html
    assert "IAM-01" in html and "DSPM-02" in html
    assert "Detailed findings" in html and "All findings" in html # both sections


def test_html_falls_back_to_cli_when_no_detail():
    # a check present in the maps but absent from FINDING_DETAIL still renders (one-line CLI)
    saved = D.FINDING_DETAIL.pop("DSPM-02")
    try:
        _, html = _render([("FAIL", "DSPM-02", "DATA", "db", "x")])
        assert "DSPM-02" in html and "Remediation" in html
    finally:
        D.FINDING_DETAIL["DSPM-02"] = saved


def test_html_clean_when_no_findings():
    _, html = _render([("PASS", "IAM-03", "IAM", "root", "ok")])
    assert "No FAIL or WARN findings" in html
