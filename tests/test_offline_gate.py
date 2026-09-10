"""aws_offline_scanner CI-gate surface: the --fail-on threshold (gate_fails) and the SARIF 2.1.0
emitter (save_sarif) that back the overwatch-iac-gate Action + the IDE plugin. Deterministic —
findings are injected, so it never depends on rule content. Pure/offline."""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_offline_scanner as sc

from _layout import module_path

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCANNER = module_path("aws_offline_scanner.py")


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
from engine import aws_guardrail as _gr                                  # noqa: E402


def _fired(scanner, policy_path):
    """Policy ids that actually fired, via the guardrail-shaped evaluation."""
    _declared, ev = sc._policy_evaluation(scanner, str(policy_path), _gr)
    return sorted(v.policy_id for v in ev.violations)


def test_policy_bridge_fires_on_finding_clause(tmp_path):
    pol = tmp_path / "policy.json"
    pol.write_text(json.dumps([
        {"id": "no-s3-critical", "match": {"finding": {"check_id_glob": "S3-*", "severity": "HIGH", "severity_op": "gte"}}},
        {"id": "never", "match": {"finding": {"check_id_glob": "ZZZ-*"}}},
        {"id": "graph-only-inert", "match": {"graph": {"kind": "S3Bucket"}}},   # no graph offline -> no fire
    ]))
    assert _fired(_scanner([_f("S3-01", "CRITICAL")]), pol) == ["no-s3-critical"]


def test_policy_bridge_clean_when_nothing_fires(tmp_path):
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps({"id": "no-low", "match": {"finding": {"severity": "LOW", "severity_op": "lte", "check_id_glob": "ZZ-*"}}}))
    assert _fired(_scanner([_f("S3-01", "HIGH")]), pol) == []


def test_a_bad_rule_is_declared_unevaluated_not_inert(tmp_path):
    """THIS TEST USED TO ASSERT THE DEFECT.

    It read `_evaluate_policies(...) == ["ok"]` — the broken policy simply vanished
    and the gate carried on. That is review finding D5 in this product's own CI
    gate: fail-open, the control silently disabled, every pipeline green, nobody the
    wiser until an audit. The old `except PolicyError: continue` even said so in its
    comment — "inert policy (never crashes the gate)" — treating a config error as a
    feature.

    A policy that could not be parsed is now DECLARED BUT UNEVALUATED, so
    `aws_guardrail.decide` demotes the run to PARTIAL and applies the strictest
    configured mode of the policies that went unread.
    """
    pol = tmp_path / "bad.json"
    pol.write_text(json.dumps([{"id": "broken", "match": {"finding": {"bogus": 1}}},
                               {"id": "ok", "match": {"finding": {"status": "FAIL"}}}]))
    declared, ev = sc._policy_evaluation(_scanner([_f("S3-01", "HIGH")]), str(pol), _gr)
    assert sorted(p.id for p in declared) == ["broken", "ok"]
    assert ev.evaluated_policy_ids == ("ok",), "the broken policy was silently skipped"
    assert ev.outcome == _gr.PARTIAL
    assert "bogus" in ev.detail, "the report must name what is wrong with the policy"

    verdict = _gr.decide(ev, declared, "production")
    assert verdict.action == _gr.BLOCK_ACTION
    assert verdict.unevaluated == ("broken",)
    assert not verdict.verified


def test_a_policy_too_malformed_to_have_an_id_is_still_named(tmp_path):
    """A count of unevaluated policies that cannot say WHICH one is unactionable by
    the engineer whose deploy it just stopped."""
    pol = tmp_path / "noid.json"
    pol.write_text(json.dumps({"match": {"finding": {"severity": "HIGH"}}}))
    declared, ev = sc._policy_evaluation(_scanner([]), str(pol), _gr)
    assert len(declared) == 1 and "no id" in declared[0].id
    assert ev.evaluated_policy_ids == ()


def test_enforcement_mode_defaults_to_block_not_audit(tmp_path):
    """`aws_guardrail.Policy` defaults to audit, which is right for a greenfield
    policy set and wrong here: a firing policy has always failed this build, so a
    default of audit would have quietly converted every existing blocking gate into
    an advisory one. Relaxation has to be written down in the policy file."""
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps([
        {"id": "plain", "match": {"finding": {"status": "FAIL"}}},
        {"id": "relaxed", "enforcement": "audit", "match": {"finding": {"status": "FAIL"}}},
        {"id": "per-env", "enforcement": {"dev": "warn"},
         "match": {"finding": {"status": "FAIL"}}},
    ]))
    declared, _ev = sc._policy_evaluation(_scanner([]), str(pol), _gr)
    by_id = {p.id: p for p in declared}
    assert by_id["plain"].mode("production") == _gr.BLOCK
    assert by_id["relaxed"].mode("production") == _gr.AUDIT
    assert by_id["per-env"].mode("dev") == _gr.WARN
    assert by_id["per-env"].mode("production") == _gr.BLOCK, "unlisted env -> strict"


def test_nothing_parsed_means_no_policy_was_actually_tested(tmp_path):
    """A findings clause over an empty catalogue reports "no match", which reads
    identically to a clean estate. It is not one — nothing was inspected."""
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps({"id": "any-fail", "match": {"finding": {"status": "FAIL"}}}))
    _declared, ev = sc._policy_evaluation(_scanner([]), str(pol), _gr,
                                          scanned_nothing=True)
    assert ev.outcome == _gr.UNAVAILABLE
    assert ev.evaluated_policy_ids == ()
    assert "no IaC files" in ev.detail


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


# ══════════════════════════════════════════════════════════════════════════════
# The gate's FAILURE MODE, end to end (FR-5 / review defect D5)
# ══════════════════════════════════════════════════════════════════════════════
# Run BY PATH, the way .github/actions/overwatch-iac-gate/entrypoint.sh does, because
# that is the invocation whose --policy support was broken: `python3 <path>/engine/
# aws_offline_scanner.py --policy p.json` put engine/ on sys.path and not the repo
# root, so `from engine import aws_policy` raised and the gate exited 2 — reported by
# the Action as "scan errored" while its own README documented --policy as supported.
def _gate(tmp_path, *args, iac='resource "aws_sns_topic" "t" { name = "t" }\n'):
    d = tmp_path / "iac"
    d.mkdir(exist_ok=True)
    if iac is not None:
        (d / "main.tf").write_text(iac)
    else:
        (d / "README.md").write_text("no iac here\n")
    r = subprocess.run([sys.executable, _SCANNER, str(d), *args],
                       capture_output=True, text=True)
    return r.returncode, (r.stderr or "")


DIRTY = 'resource "aws_s3_bucket" "b" {\n  acl = "public-read-write"\n}\n'


def _pol(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj))
    return str(p)


BROKEN = {"id": "P-TYPO", "match": {"finding": {"sevrity": "HIGH"}}}
NEVER = {"id": "P-NEVER", "match": {"finding": {"check_id_glob": "ZZZ-*"}}}


# ── the contract that must not change ───────────────────────────────────────
def test_a_clean_tree_still_exits_0(tmp_path):
    assert _gate(tmp_path, "--fail-on", "HIGH")[0] == 0


def test_a_severity_breach_still_exits_1(tmp_path):
    assert _gate(tmp_path, "--fail-on", "HIGH", iac=DIRTY)[0] == 1


def test_a_firing_policy_still_exits_1(tmp_path):
    pol = _pol(tmp_path, "fire.json",
               {"id": "P", "match": {"finding": {"status": "FAIL"}}})
    assert _gate(tmp_path, "--fail-on", "CRITICAL", "--policy", pol, iac=DIRTY)[0] == 1


def test_policy_gating_works_when_run_by_path(tmp_path):
    """The latent bug. This is the Action's exact invocation shape, and it could not
    load the policy engine at all."""
    pol = _pol(tmp_path, "p.json", NEVER)
    rc, err = _gate(tmp_path, "--fail-on", "HIGH", "--policy", pol)
    assert "requires the OverWatch policy engine" not in err
    assert rc == 0


# ── an evaluation that did not happen is never an allow ─────────────────────
def test_an_unparseable_policy_blocks_instead_of_vanishing(tmp_path):
    pol = _pol(tmp_path, "bad.json", BROKEN)
    rc, err = _gate(tmp_path, "--fail-on", "HIGH", "--policy", pol)
    assert rc == 1, "a policy that could not be parsed was silently skipped"
    assert "did NOT evaluate" in err and "P-TYPO" in err


def test_an_unparseable_policy_in_audit_mode_is_degraded_not_passed(tmp_path):
    """A policy in audit mode never blocks, so an unreachable one must not start
    blocking on its behalf — but it is not a pass either. Exit 2: proceeded without
    a completed evaluation."""
    pol = _pol(tmp_path, "audit.json", dict(BROKEN, enforcement="audit"))
    rc, err = _gate(tmp_path, "--fail-on", "HIGH", "--policy", pol)
    assert rc == 2
    assert "ALLOWED WITHOUT EVALUATION" in err


def test_a_severity_breach_cannot_be_degraded_by_a_broken_policy_file(tmp_path):
    """The severity gate is local arithmetic over findings — it always completes, so
    a breach it found blocks on its own merits. Otherwise a malformed policy file
    would be a way to turn a real CRITICAL into an exit 2 somebody waves through."""
    pol = _pol(tmp_path, "audit.json", dict(BROKEN, enforcement="audit"))
    assert _gate(tmp_path, "--fail-on", "CRITICAL", "--policy", pol, iac=DIRTY)[0] == 1


def test_enforcement_is_per_environment(tmp_path):
    pol = _pol(tmp_path, "env.json",
               dict(BROKEN, enforcement={"production": "block", "dev": "audit"}))
    assert _gate(tmp_path, "--policy", pol, "--environment", "production")[0] == 1
    assert _gate(tmp_path, "--policy", pol, "--environment", "dev")[0] == 2


# ── a gate that inspected nothing ───────────────────────────────────────────
def test_scanning_no_iac_files_is_not_a_pass(tmp_path):
    """`scanned_files` was tracked and the gate ignored it, so pointing the Action at
    a path with no Terraform or CloudFormation exited 0 with a green check. Nothing
    was inspected; that is not evidence of anything."""
    rc, err = _gate(tmp_path, "--fail-on", "HIGH", iac=None)
    assert rc == 2
    assert "inspected nothing is not a pass" in err


def test_allow_empty_makes_an_empty_target_legitimate(tmp_path):
    """Monorepo CI runs the gate on paths that may genuinely hold no IaC, so the
    strict default needs an explicit, written-down opt-out rather than no opt-out."""
    assert _gate(tmp_path, "--fail-on", "HIGH", "--allow-empty", iac=None)[0] == 0


def test_no_iac_files_with_policies_declared_blocks(tmp_path):
    pol = _pol(tmp_path, "p.json", NEVER)
    rc, err = _gate(tmp_path, "--fail-on", "HIGH", "--policy", pol, iac=None)
    assert rc == 1
    assert "no policy was evaluated against anything" in err


# ── break-glass: attributed, justified, time-boxed ──────────────────────────
def _bg(*, actor="krishnendu",
        reason="shipping the fix for the policy schema itself", hours="2"):
    return ["--break-glass-actor", actor, "--break-glass-reason", reason,
            "--break-glass-hours", hours]


def test_a_valid_override_proceeds_but_never_as_a_pass(tmp_path):
    pol = _pol(tmp_path, "bad.json", BROKEN)
    rc, err = _gate(tmp_path, "--fail-on", "HIGH", "--policy", pol, *_bg())
    assert rc == 2, "an override produced a clean exit 0"
    assert "ALLOWED UNDER OVERRIDE" in err


def test_an_expired_override_does_not_degrade_to_a_warning(tmp_path):
    pol = _pol(tmp_path, "bad.json", BROKEN)
    rc, _err = _gate(tmp_path, "--policy", pol, *_bg(hours="-1"))
    assert rc == 1


def test_a_thin_justification_is_refused(tmp_path):
    pol = _pol(tmp_path, "bad.json", BROKEN)
    rc, err = _gate(tmp_path, "--policy", pol, *_bg(reason="temp"))
    assert rc == 2 and "20 characters" in err


def test_partial_override_flags_are_refused(tmp_path):
    """Fail-closed must not become fail-open one flag at a time."""
    pol = _pol(tmp_path, "bad.json", BROKEN)
    rc, err = _gate(tmp_path, "--policy", pol, "--break-glass-actor", "k")
    assert rc == 2 and "must be given together" in err


# ── the central record (OW2-GR-005) ─────────────────────────────────────────
def test_the_gate_record_says_what_was_not_checked(tmp_path):
    pol = _pol(tmp_path, "bad.json", BROKEN)
    rec = tmp_path / "rec.json"
    rc, _err = _gate(tmp_path, "--fail-on", "HIGH", "--policy", pol,
                     "--gate-record", str(rec))
    assert rc == 1 and rec.exists()
    r = json.loads(rec.read_text())
    assert r["action"] == "block" and r["outcome"] == "partial"
    assert r["verified"] is False
    assert r["unevaluated_policies"] == ["P-TYPO"]
    assert r["exit_code"] == 1
    assert r["scanned_files"] == 1
    assert r["severity_gate_failed"] is False


def test_the_gate_record_records_the_override_and_who_made_it(tmp_path):
    pol = _pol(tmp_path, "bad.json", BROKEN)
    rec = tmp_path / "rec.json"
    _gate(tmp_path, "--policy", pol, "--gate-record", str(rec), *_bg())
    r = json.loads(rec.read_text())
    assert r["override"]["actor"] == "krishnendu"
    assert r["override"]["expires_epoch"] > 0
    assert r["verified"] is False


def test_an_unwritable_gate_record_is_an_env_error_not_a_gate_breach(tmp_path):
    """Same rule as the SARIF writer above: a path problem must never be reported as
    a policy breach."""
    pol = _pol(tmp_path, "p.json", NEVER)
    bad = tmp_path / "no-such-dir" / "rec.json"
    rc, _err = _gate(tmp_path, "--fail-on", "HIGH", "--policy", pol,
                     "--gate-record", str(bad))
    assert rc == 2
