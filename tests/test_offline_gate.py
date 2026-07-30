"""aws_offline_scanner CI-gate surface: the --fail-on threshold (gate_fails) and the SARIF 2.1.0
emitter (save_sarif) that back the overwatch-iac-gate Action + the IDE plugin. Deterministic —
findings are injected, so it never depends on rule content. Pure/offline."""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_offline_scanner as sc

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCANNER = os.path.join(_ROOT, "aws_offline_scanner.py")


def _f(rule_id, severity, file_path="main.tf", line_num=10):
    return sc.Finding(rule_id, f"{rule_id} name", "S3", severity, file_path, line_num,
                      "  bucket_acl = public", f"{rule_id} description", f"Fix {rule_id}",
                      cwe="CWE-284", cve=None)


def _scanner(findings):
    s = sc.AWSIaCScanner()
    s.findings = findings
    return s


# ── the gate ────────────────────────────────────────────────────────────────────
def test_gate_fail_on_high_trips_on_high_and_critical():
    assert _scanner([_f("R1", "HIGH")]).gate_fails("HIGH") is True
    assert _scanner([_f("R1", "CRITICAL")]).gate_fails("HIGH") is True
    assert _scanner([_f("R1", "MEDIUM"), _f("R2", "LOW")]).gate_fails("HIGH") is False
    assert _scanner([]).gate_fails("HIGH") is False


def test_gate_threshold_direction_is_not_inverted():
    # fail-on LOW trips on ANYTHING >= LOW; fail-on CRITICAL only on CRITICAL
    s = _scanner([_f("R1", "MEDIUM")])
    assert s.gate_fails("LOW") is True and s.gate_fails("CRITICAL") is False
    assert _scanner([_f("R1", "CRITICAL")]).gate_fails("CRITICAL") is True


# ── SARIF ─────────────────────────────────────────────────────────────────────────
def test_sarif_shape_levels_and_real_lines(tmp_path):
    out = tmp_path / "out.sarif"
    _scanner([_f("R1", "CRITICAL", "a.tf", 12), _f("R1", "CRITICAL", "b.tf", 3),
              _f("R2", "MEDIUM", "c.tf", 7), _f("R3", "LOW", "d.tf", 1)]).save_sarif(str(out))
    doc = json.loads(out.read_text())
    assert doc["version"] == "2.1.0" and len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "OverWatch IaC Scanner"
    # rules deduped by rule_id (R1/R2/R3), results one-per-finding (4)
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {"R1", "R2", "R3"}
    assert len(run["results"]) == 4
    r0 = run["results"][0]
    assert r0["level"] == "error"                          # CRITICAL -> error
    assert r0["locations"][0]["physicalLocation"]["region"]["startLine"] == 12  # real line
    assert r0["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "a.tf"
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels["R2"] == "warning" and levels["R3"] == "note"
    sev = {ru["id"]: ru["properties"]["security-severity"] for ru in run["tool"]["driver"]["rules"]}
    assert sev["R1"] == "9.5"


def test_sarif_cfn_no_line_falls_back_to_line_1(tmp_path):
    out = tmp_path / "cfn.sarif"
    _scanner([_f("CF1", "HIGH", "stack.yaml", None)]).save_sarif(str(out))
    doc = json.loads(out.read_text())
    assert doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_sarif_backslash_paths_normalized(tmp_path):
    out = tmp_path / "w.sarif"
    _scanner([_f("R1", "HIGH", "infra\\prod\\main.tf", 5)]).save_sarif(str(out))
    doc = json.loads(out.read_text())
    assert doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "infra/prod/main.tf"


# ── --policy bridge (findings-level policy-as-code over IaC findings) ─────────────
def test_policy_bridge_fires_on_finding_clause(tmp_path):
    pol = tmp_path / "policy.json"
    pol.write_text(json.dumps([
        {"id": "no-s3-critical", "match": {"finding": {"check_id_glob": "S3-*", "severity": "HIGH", "severity_op": "gte"}}},
        {"id": "never", "match": {"finding": {"check_id_glob": "ZZZ-*"}}},
        {"id": "graph-only-inert", "match": {"graph": {"kind": "S3Bucket"}}},   # no graph offline -> no fire
    ]))
    hits = sc._evaluate_policies(_scanner([_f("S3-01", "CRITICAL")]), str(pol))
    assert hits == ["no-s3-critical"]                     # never/graph-only did not fire


def test_policy_bridge_clean_when_nothing_fires(tmp_path):
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps({"id": "no-low", "match": {"finding": {"severity": "LOW", "severity_op": "lte", "check_id_glob": "ZZ-*"}}}))
    assert sc._evaluate_policies(_scanner([_f("S3-01", "HIGH")]), str(pol)) == []


def test_policy_bridge_bad_rule_is_inert(tmp_path):
    pol = tmp_path / "bad.json"
    pol.write_text(json.dumps([{"id": "broken", "match": {"finding": {"bogus": 1}}},
                               {"id": "ok", "match": {"finding": {"status": "FAIL"}}}]))
    assert sc._evaluate_policies(_scanner([_f("S3-01", "HIGH")]), str(pol)) == ["ok"]


# ── exit-code contract (an unwritable report is an ENV error, not a gate breach) ─
def test_unwritable_sarif_path_exits_2_not_1(tmp_path):
    tf = tmp_path / "main.tf"
    tf.write_text('resource "aws_s3_bucket" "b" { bucket = "x" }\n')
    bad = tmp_path / "no-such-dir" / "o.sarif"     # parent dir does not exist -> OSError on open
    r = subprocess.run([sys.executable, _SCANNER, str(tf), "--sarif", str(bad), "--fail-on", "LOW"],
                       capture_output=True, text=True)
    assert r.returncode == 2                        # env error, NEVER 1 (which the Action reads as a gate breach)


def test_missing_target_exits_2():
    r = subprocess.run([sys.executable, _SCANNER, os.path.join(_ROOT, "does-not-exist.tf")],
                       capture_output=True, text=True)
    assert r.returncode == 2
