"""A ratchet on the test suite itself: tests may be added, never silently removed.

WHY THIS EXISTS. Slice 3.3 overwrote ``tests/test_mcp.py`` — slice 1.5's 402-line suite
covering decision **D6**, the enforcement boundary on OverWatch's own local MCP server:
that it refuses to start without an explicit acknowledgement, redacts identifiers by
default, and audits every call. Thirty-four test functions became twenty-two, and
**nothing objected**. Two full runs reported green, and both were telling the truth
about what they ran. The total even went *up* — 3,060 to 3,097 — because the new slice
added more tests than the overwrite destroyed.

That is the shape of the failure worth naming: **a rising number is not evidence that
nothing was lost.** This codebase already guards against silent regressions everywhere
it decided they matter — ``test_check_maps_lockstep`` on the metadata maps,
``test_console_node_parity`` on graph node kinds, ``test_perm_ledger`` on the IAM
surface, ``test_zero_telemetry`` on what may be ingested. Every one of them exists
because a confident wrong answer shipped once. The tests themselves were the one
load-bearing artefact with no such guard, which is how the enforcement tests for a
deliberate product decision came to be deleted by accident.

THE RULE, and it is deliberately blunt:

  * every test module carries a floor — the number of ``def test_`` functions it had
    when last ratcheted;
  * a module below its floor **fails**, because a test function that existed is not
    allowed to quietly stop existing;
  * a module whose floor no longer exists **fails**, because deleting a whole file is
    the same loss in a larger unit;
  * a new module with no floor **fails**, so joining the suite is a deliberate act;
  * a floor that has fallen behind **fails**, because a floor that never rises decays
    into permission to delete everything added after it.

The last one is the friction, and it is the point. Adding tests means bumping a number,
which takes one command::

    python tests/test_suite_ratchet.py --update

Counting is done with ``ast`` rather than by collecting through pytest: the count must
not depend on fixtures importing cleanly, and a module that fails to import should be
caught by the suite proper rather than silently reading as zero here. ``@parametrize``
expansion is deliberately NOT counted — the floor tracks authored test FUNCTIONS, which
is the unit a person deletes.
"""
from __future__ import annotations

import ast
import os
import pathlib
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TESTS_DIR = pathlib.Path(__file__).resolve().parent


def _count(path: pathlib.Path) -> int:
    """Authored ``def test_*`` functions in one module, nested classes included."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return -1                      # unreadable: reported, never silently zero
    return sum(1 for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
               and n.name.startswith("test_"))


_CACHE: dict = {}


def _modules() -> dict:
    """Counts for every module, parsed ONCE.

    Memoized because the per-module check is parametrized over 181 entries, and an
    un-cached implementation re-parses the whole tests/ tree for each one — 30k+ file
    parses, six minutes of wall clock, to compute the same dict 181 times. A guard that
    doubles the suite's runtime is a guard people start skipping."""
    if not _CACHE:
        _CACHE.update({p.name: _count(p) for p in sorted(TESTS_DIR.glob("test_*.py"))
                       if p.name != pathlib.Path(__file__).name})
    return _CACHE


# ── the floors ──────────────────────────────────────────────────────────────
# Generated, never typed by hand: python tests/test_suite_ratchet.py --update
FLOORS = {
    "test_action_contract.py": 4,
    "test_agency.py": 20,
    "test_agency_wiring.py": 18,
    "test_agentcore.py": 23,
    "test_agentcore_gateway.py": 33,
    "test_agentcore_wiring.py": 24,
    "test_agentmemory.py": 16,
    "test_agentmemory_wiring.py": 15,
    "test_ai_frameworks_crosswalk.py": 14,
    "test_ai_threat_section.py": 9,
    "test_aiguard.py": 26,
    "test_aiguard_wiring.py": 21,
    "test_ailog.py": 23,
    "test_ailog_wiring.py": 21,
    "test_aipath_conditional.py": 10,
    "test_aiprotect.py": 19,
    "test_aiprotect_wiring.py": 15,
    "test_airules.py": 27,
    "test_aispm.py": 18,
    "test_aispm_graph.py": 13,
    "test_authn.py": 20,
    "test_aws_kube.py": 14,
    "test_backend_pg.py": 21,
    "test_blast_radius.py": 12,
    "test_cbom.py": 29,
    "test_cdr_api.py": 10,
    "test_cdr_ingest.py": 21,
    "test_cdr_state.py": 8,
    "test_check_maps_lockstep.py": 10,
    "test_checkdef.py": 23,
    "test_cnapp_api.py": 7,
    "test_cnapp_cfn.py": 5,
    "test_cnapp_connectors.py": 50,
    "test_cnapp_connectors_api.py": 6,
    "test_cnapp_onboarding.py": 8,
    "test_cnapp_phase1.py": 32,
    "test_cnapp_registry.py": 16,
    "test_cnapp_scheduling.py": 25,
    "test_cnapp_service.py": 11,
    "test_cnapp_validate.py": 12,
    "test_cnapp_worker.py": 8,
    "test_codetocloud.py": 18,
    "test_compliance_api.py": 4,
    "test_compliance_crosswalk.py": 24,
    "test_console_node_parity.py": 13,
    "test_controls.py": 15,
    "test_copilot.py": 18,
    "test_copilot_ai_vocabulary.py": 6,
    "test_copilot_api.py": 9,
    "test_correlate.py": 31,
    "test_correlate_frozen.py": 2,
    "test_cost_findings.py": 11,
    "test_cra_crosswalk.py": 11,
    "test_credential_report_timing.py": 10,
    "test_custom_controls.py": 24,
    "test_decisions.py": 15,
    "test_deepplane.py": 44,
    "test_dspm.py": 12,
    "test_dspm_surfaces.py": 5,
    "test_ed25519.py": 8,
    "test_edr.py": 22,
    "test_edr_service.py": 15,
    "test_effperm.py": 32,
    "test_engine_eol.py": 15,
    "test_evidence.py": 28,
    "test_evidence_bundle.py": 46,
    "test_evidence_wiring.py": 8,
    "test_exposure.py": 56,
    "test_extsvc.py": 51,
    "test_extsvc2_wiring.py": 39,
    "test_extsvc3.py": 37,
    "test_extsvc4.py": 34,
    "test_extsvc5.py": 35,
    "test_extsvc6.py": 36,
    "test_extsvc7.py": 36,
    "test_extsvc_wiring.py": 29,
    "test_finding_detail.py": 14,
    "test_forensics.py": 6,
    "test_forensics_api.py": 4,
    "test_frontend_contract.py": 7,
    "test_graph_from_dict.py": 9,
    "test_graph_neptune.py": 14,
    "test_graph_reverse.py": 10,
    "test_guardrail_coverage.py": 11,
    "test_iam_surface.py": 11,
    "test_ingest_aidr.py": 21,
    "test_ingest_aidr_wiring.py": 13,
    "test_ingest_api.py": 5,
    "test_ingest_connectors.py": 7,
    "test_ingest_enrich.py": 13,
    "test_ingest_hardening.py": 14,
    "test_ingest_parsers.py": 24,
    "test_ingest_rbac.py": 3,
    "test_ingest_reachability.py": 8,
    "test_ingest_service.py": 11,
    "test_ingest_snapshot.py": 6,
    "test_ingest_state.py": 8,
    "test_layer_fetch.py": 14,
    "test_leastpriv.py": 13,
    "test_leastpriv_wiring.py": 5,
    "test_license.py": 10,
    "test_live_scanner.py": 71,
    "test_malware.py": 13,
    "test_malware_service.py": 8,
    "test_marketplace_metering.py": 5,
    "test_mcp.py": 34,
    "test_mcp_drift.py": 16,
    "test_mcp_provenance.py": 23,
    "test_mcp_registry.py": 23,
    "test_mcp_wiring.py": 24,
    "test_modelartifact.py": 28,
    "test_modelartifact_wiring.py": 20,
    "test_multitenancy_connectors.py": 11,
    "test_multitenancy_control_plane.py": 9,
    "test_multitenancy_isolation.py": 12,
    "test_multitenancy_metering.py": 6,
    "test_multitenancy_rbac.py": 9,
    "test_multitenancy_schema.py": 7,
    "test_multitenancy_store.py": 9,
    "test_neptune_loader.py": 9,
    "test_nhi.py": 41,
    "test_nitro.py": 23,
    "test_nitro_wiring.py": 16,
    "test_offline_gate.py": 10,
    "test_packaging_server.py": 7,
    "test_pentest_ingest.py": 23,
    "test_pentest_wiring.py": 25,
    "test_perimeter.py": 40,
    "test_perimeter_wiring.py": 25,
    "test_perm_ledger.py": 19,
    "test_perm_ledger_wiring.py": 13,
    "test_phase0_ai_defects.py": 8,
    "test_phase0_region_coverage.py": 10,
    "test_phase0_slice04.py": 19,
    "test_phase1_quickwins.py": 68,
    "test_phase2_misconfigs.py": 67,
    "test_phase3_appdeps.py": 28,
    "test_phase3_fargate.py": 21,
    "test_phase3_flowlog.py": 31,
    "test_phase3_kspm_kiem.py": 30,
    "test_phase4_containers.py": 28,
    "test_phase4_ecr.py": 11,
    "test_phase4_fixes.py": 17,
    "test_phase5_elasticache.py": 10,
    "test_phase5_fixes.py": 7,
    "test_phase5_graph.py": 5,
    "test_phase5_integration.py": 17,
    "test_phase5_opensearch.py": 8,
    "test_phase5_rds_aurora.py": 13,
    "test_phase5_redshift.py": 13,
    "test_phase6_ami.py": 9,
    "test_phase6_classic_elb.py": 10,
    "test_phase6_compute.py": 17,
    "test_phase6_ecs.py": 13,
    "test_phase6_eks.py": 8,
    "test_phase6_fixes.py": 10,
    "test_phase6_integration.py": 11,
    "test_phase6_s3_policy.py": 9,
    "test_phase6_sagemaker.py": 13,
    "test_phase6_signing.py": 10,
    "test_phase6_storage.py": 13,
    "test_phase6_vpc.py": 10,
    "test_phase6_waf_cfn.py": 9,
    "test_phase7_dspm.py": 40,
    "test_phase7_fixes.py": 10,
    "test_phase7_identity.py": 11,
    "test_phase7_integration.py": 4,
    "test_phase7_l7.py": 25,
    "test_phase8_winvuln.py": 40,
    "test_policy.py": 15,
    "test_policy_service.py": 12,
    "test_projects.py": 11,
    "test_qr.py": 9,
    "test_rbac_roles.py": 20,
    "test_registry_api.py": 6,
    "test_registry_connector_service.py": 8,
    "test_registry_connectors.py": 19,
    "test_registry_import_order.py": 3,
    "test_registry_oci.py": 24,
    "test_registry_persist.py": 5,
    "test_registry_sbom.py": 5,
    "test_registry_scan.py": 10,
    "test_registry_sidescan.py": 6,
    "test_remediate.py": 14,
    "test_sagemaker_depth.py": 38,
    "test_sagemaker_wiring.py": 29,
    "test_sbom_diff.py": 8,
    "test_sdk_pin.py": 7,
    "test_secrets.py": 9,
    "test_secrets_collector.py": 7,
    "test_seed_demo_data.py": 48,
    "test_segmentation.py": 28,
    "test_segmentation_wiring.py": 14,
    "test_shadowai.py": 22,
    "test_shadowai_wiring.py": 18,
    "test_sidescan.py": 41,
    "test_sidescan_ebs.py": 28,
    "test_sidescan_fs.py": 13,
    "test_spa_build_mode.py": 7,
    "test_state.py": 22,
    "test_state_dialect.py": 17,
    "test_supplychain_parsers.py": 9,
    "test_supplychain_state.py": 11,
    "test_terraform_parity.py": 9,
    "test_toolpoison.py": 31,
    "test_toprisks_categories.py": 7,
    "test_totp.py": 18,
    "test_toxicflow.py": 28,
    "test_toxicflow_wiring.py": 17,
    "test_unused.py": 21,
    "test_user_admin.py": 19,
    "test_vectorstore.py": 31,
    "test_vectorstore_wiring.py": 23,
    "test_vex_standalone.py": 12,
    "test_vulndb_bundle.py": 7,
    "test_vulndb_verify.py": 7,
    "test_wql.py": 22,
    "test_wql_parity.py": 4,
    "test_zero_telemetry.py": 20,
    "test_ztmm.py": 28,
    "test_ztmm_wiring.py": 8,
}  # @@FLOORS@@


def test_every_module_carries_a_floor():
    """Joining the suite is a deliberate act. Without this, a module added today has no
    floor tomorrow, and the ratchet quietly stops covering the newest code — which is
    exactly the code most likely to be rewritten."""
    unregistered = sorted(set(_modules()) - set(FLOORS))
    assert not unregistered, (
        f"{len(unregistered)} test module(s) have no floor: {unregistered}. "
        f"Run `python tests/test_suite_ratchet.py --update` to register them.")


def test_no_module_has_disappeared():
    """Deleting a whole file is the same loss as emptying one, in a larger unit."""
    missing = sorted(set(FLOORS) - set(_modules()))
    assert not missing, (
        f"{len(missing)} test module(s) vanished: {missing}. If a module was renamed, "
        f"run `--update`; if tests were genuinely retired, say so in the commit — but "
        f"do not let it happen as a side effect of writing a new file over an old path.")


@pytest.mark.parametrize("module", sorted(FLOORS))
def test_no_module_lost_a_test(module):
    """The one that would have caught the D6 deletion: test_mcp.py went 34 -> 22."""
    live = _modules()
    if module not in live:
        pytest.skip("covered by test_no_module_has_disappeared")
    assert live[module] >= FLOORS[module], (
        f"{module} has {live[module]} test functions but its floor is "
        f"{FLOORS[module]} — {FLOORS[module] - live[module]} were removed. If a test "
        f"was deliberately retired, lower the floor in the same commit that explains "
        f"why. If you are writing a new file, check whether this path already held "
        f"something.")


def test_no_floor_has_fallen_behind():
    """A floor that never rises decays into permission to delete everything added after
    it. Same discipline as the check-map backlog, which fails when an entry becomes
    redundant rather than letting the list rot into fiction."""
    live = _modules()
    stale = {m: (FLOORS[m], live[m]) for m in FLOORS
             if m in live and live[m] > FLOORS[m]}
    assert not stale, (
        f"{len(stale)} floor(s) are below the tests that now exist: "
        f"{ {m: f'{lo}->{hi}' for m, (lo, hi) in sorted(stale.items())} }. "
        f"Run `python tests/test_suite_ratchet.py --update`.")


def test_every_module_parses():
    """A module that stops parsing would otherwise read as zero tests and trip the
    floor with a misleading message."""
    broken = sorted(m for m, n in _modules().items() if n < 0)
    assert not broken, f"unparseable test module(s): {broken}"


# ── regeneration ────────────────────────────────────────────────────────────
def _rewrite() -> int:
    """Rewrite the FLOORS literal from the tree. Floors only ever RISE here — an
    existing floor is never lowered by --update, because lowering one is a decision
    somebody must make in a commit message, not a side effect of running a script."""
    path = pathlib.Path(__file__)
    src = path.read_text(encoding="utf-8")
    live = _modules()
    merged = dict(FLOORS)
    for mod, n in live.items():
        if n >= 0:
            merged[mod] = max(n, FLOORS.get(mod, 0))
    for gone in set(merged) - set(live):
        merged.pop(gone)
    body = "\n".join(f'    "{m}": {merged[m]},' for m in sorted(merged))
    start = src.index("FLOORS = {")
    end = src.index("@@FLOORS@@", start) + len("@@FLOORS@@")
    # `end` already points PAST the marker, so the original `src[end + 2:]` ate two
    # more characters on every run. Harmless the first time; on the second it deleted
    # the newlines before the next `def`, leaving a file that would not parse — and the
    # symptom was the whole suite failing to COLLECT, which looks nothing like the
    # cause. A regeneration script that damages the file it regenerates is worse than
    # no script, so `test_update_is_idempotent` now runs it twice and re-parses.
    new = src[:start] + "FLOORS = {\n" + body + "\n}  # @@FLOORS@@" + src[end:]
    _CACHE.clear()
    path.write_text(new, encoding="utf-8", newline="")
    return len(merged)


if __name__ == "__main__":
    if "--update" in sys.argv:
        print(f"floors written for {_rewrite()} test modules")
    else:
        print(f"{len(_modules())} test modules, "
              f"{sum(n for n in _modules().values() if n > 0)} test functions")


def test_update_is_idempotent():
    """The guard on the guard.

    `--update` rewrites this very file, and its first version ate two characters past
    the marker on every run: correct once, and on the second run it deleted the newlines
    before the next `def` and left a module that would not parse. The symptom was the
    entire suite failing to COLLECT, which looks nothing like the cause and lands in the
    one file nobody re-reads.

    Running the rewrite twice against a copy and re-parsing is the cheapest possible
    proof that regenerating the floors cannot break the floors."""
    import ast
    import shutil
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "test_suite_ratchet.py")
        shutil.copy(__file__, target)
        # Real sibling modules to floor. Without them TESTS_DIR (which resolves
        # relative to the COPY) holds nothing, --update writes an empty block, and the
        # test would pass while exercising none of the rewrite it exists to check.
        for name, n in (("test_alpha.py", 3), ("test_beta.py", 2)):
            with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
                fh.write("".join(f"def test_{i}():\n    pass\n\n" for i in range(n)))
        for _ in range(2):
            subprocess.run([sys.executable, target, "--update"],
                           cwd=tmp, capture_output=True, check=True)
            ast.parse(open(target, encoding="utf-8").read())
        body = open(target, encoding="utf-8").read()
    # Not a count of the marker string — it also appears in _rewrite's own source and
    # in this test. What matters is that the generated BLOCK is still well-formed and
    # still separated from the code after it, which is precisely what the off-by-two
    # destroyed.
    assert "\n}  # @@FLOORS@@\n\n\ndef " in body
    # And the floors survived, with the right counts, rather than the block being
    # emptied -- which is what an un-exercised rewrite would also produce.
    assert '"test_alpha.py": 3,' in body
    assert '"test_beta.py": 2,' in body
