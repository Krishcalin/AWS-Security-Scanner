"""CIS AWS Storage Services v1.0.0 — the mapping, the new checks, and one refusal.

Three jobs, in descending order of how much they matter.

1. THE REFUSAL. Two recommendations in this benchmark would reduce security if
   followed. `test_no_check_ever_cites_an_unsafe_recommendation` is the guard that
   keeps them out of the catalogue: 2.2 directs the reader to open SSH to the world
   and 3.5 restricts EFS mount targets to port 22, which EFS does not use. Both are
   the sort of row that looks like an unbuilt backlog item to anyone skimming the
   mapping later, so the mapping records WHY they must stay unbuilt and this test
   makes citing them a build failure.

2. BOTH-DIRECTION AGREEMENT between the mapping and the catalogue, the same contract
   the Database and Foundations mappings hold. The reverse direction is the one that
   rots: a check renamed or retired leaves a mapping quietly citing an id nobody
   emits.

3. DRIVING TESTS for the six new checks. `MAX_NEVER_OBSERVED` is 0 as of tranche 8,
   so a check shipped without one fails the build rather than joining a backlog.
"""
from __future__ import annotations

import os
import subprocess
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import aws_cis_storage as S                              # noqa: E402
from engine import aws_cis_storage_map as M                          # noqa: E402
from engine import aws_live_scanner as A                             # noqa: E402
from test_live_scanner import make_scanner                           # noqa: E402
from test_unproven_checks_tranche5 import _ids, _renders             # noqa: E402

OWN = "123456789012"
REGION = "us-east-1"
DOC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "docs", "CIS_STORAGE_BENCHMARK.md")
GENERATOR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "scripts", "cis_storage_benchmark.py")


# ═════════════════════════════════════════════════════════════════════════════
# 1. The refusal
# ═════════════════════════════════════════════════════════════════════════════
def test_the_unsafe_rows_are_exactly_the_two_that_were_read_and_refused():
    """Pinned by number. If a later reading of the document finds a third, it goes
    here deliberately; if somebody decides one of these is fine after all, deleting
    it from the mapping has to be a deliberate act rather than a quiet edit."""
    assert M.by_verdict(M.UNSAFE) == ("2.2", "3.5")


def test_no_check_ever_cites_an_unsafe_recommendation():
    """The guard this whole module exists for.

    2.2's audit procedure directs the reader to open SSH, HTTP and HTTPS and to
    allow traffic from anywhere -- the exact state SEG-01, SEG-06 and VPC-05 FAIL
    on. 3.5 directs the reader to restrict EFS mount-target ingress to port 22,
    which is SSH; EFS mount targets serve NFS on 2049, so a group built to that
    instruction blocks every legitimate mount and admits nothing useful to an
    attacker. Citing either would put this product's name behind the advice."""
    unsafe = set(M.by_verdict(M.UNSAFE))
    cited = {
        cid: keys["CIS-STORAGE"]
        for cid, keys in A.COMPLIANCE_MAP.items()
        if keys.get("CIS-STORAGE") in unsafe
    }
    assert not cited, (
        f"checks cite an UNSAFE recommendation: {cited}. Those rows are recorded "
        f"as UNSAFE because following the source's own guidance would reduce "
        f"security -- see engine/aws_cis_storage_map.py")


def test_an_unsafe_row_names_no_check():
    """An UNSAFE row with a check attached would read as 'we built this', which is
    the opposite of what the verdict means."""
    for rec in M.by_verdict(M.UNSAFE):
        assert not M.checks_for(rec), f"{rec} is UNSAFE and names a check"


# ═════════════════════════════════════════════════════════════════════════════
# 2. Mapping invariants
# ═════════════════════════════════════════════════════════════════════════════
def test_every_recommendation_is_present_exactly_once_and_the_numbering_is_dense():
    for num, _name, declared in M.SECTIONS:
        nums = sorted(int(r.split(".", 1)[1])
                      for r in M.RECOMMENDATIONS if r.split(".", 1)[0] == num)
        assert nums == list(range(1, declared + 1)), (
            f"section {num} is {nums}, expected 1..{declared}")


def test_the_section_counts_sum_to_the_benchmark_total():
    assert sum(c for _n, _l, c in M.SECTIONS) == len(M.RECOMMENDATIONS) == 56


def test_every_verdict_is_one_of_the_declared_ones_and_every_one_is_used():
    """An unused verdict is the vocabulary equivalent of a registered check that
    cannot fire: it reads as a distinction the mapping draws and does not."""
    used = {row[1] for row in M.RECOMMENDATIONS.values()}
    assert used <= set(M.VERDICTS), f"unknown verdicts: {used - set(M.VERDICTS)}"
    assert used == set(M.VERDICTS), f"declared but unused: {set(M.VERDICTS) - used}"


def test_every_check_named_in_the_mapping_exists_in_the_catalogue():
    named = {c for row in M.RECOMMENDATIONS.values() for c in row[2]}
    missing = sorted(c for c in named if c not in A.CHECK_SEVERITY)
    assert not missing, f"mapping cites checks that do not exist: {missing}"


def test_covered_means_a_check_is_named_and_nothing_else_names_one():
    for rec, (_label, verdict, checks, _note) in M.RECOMMENDATIONS.items():
        if verdict == M.COVERED:
            assert checks, f"{rec} is covered and names no check"
        if verdict in (M.NO_CHECK, M.BLOCKED, M.NO_AUDIT, M.VACUOUS, M.UNSAFE):
            assert not checks, (
                f"{rec} is {verdict} and names {checks} -- those verdicts mean "
                f"nothing decides it")


def test_every_cis_storage_key_matches_the_mapping():
    """Forward direction: a key on a check must name a recommendation that exists
    and that actually lists the check."""
    for cid, keys in A.COMPLIANCE_MAP.items():
        rec = keys.get("CIS-STORAGE")
        if not rec:
            continue
        assert rec in M.RECOMMENDATIONS, f"{cid} cites unknown {rec}"
        assert cid in M.checks_for(rec), (
            f"{cid} cites {rec}, which does not list it")


def test_every_covered_storage_check_carries_the_key():
    """Reverse direction -- the one that rots. A check named by a covered row, and
    belonging to that row's own service section, must carry the citation."""
    for rec, (_label, verdict, checks, _note) in M.RECOMMENDATIONS.items():
        if verdict != M.COVERED:
            continue
        for cid in checks:
            fam = cid.rsplit("-", 1)[0]
            if M.FAMILY_SECTION.get(fam) != rec.split(".", 1)[0]:
                continue
            assert A.COMPLIANCE_MAP.get(cid, {}).get("CIS-STORAGE") == rec, (
                f"{cid} is the covering check for {rec} and does not cite it")


def test_the_key_only_lands_on_storage_checks():
    """EC2-17 is named by 2.4 and must NOT take the key: it is a Compute-family
    check and keeps its CIS-COMPUTE citation. Without this, a benchmark mapping
    quietly re-labels checks belonging to other pillars."""
    for cid, keys in A.COMPLIANCE_MAP.items():
        if "CIS-STORAGE" not in keys:
            continue
        fam = cid.rsplit("-", 1)[0]
        assert fam in M.FAMILY_SECTION, (
            f"{cid} carries CIS-STORAGE but {fam} is not one of this benchmark's "
            f"service families {sorted(M.FAMILY_SECTION)}")
    assert "CIS-STORAGE" not in A.COMPLIANCE_MAP.get("EC2-17", {})


def test_the_new_backup_checks_deliberately_carry_no_key():
    """BCK-04 and BCK-05 answer no recommendation in this benchmark, and that is
    the finding: its AWS Backup section asks that backups exist and never that they
    survive the region or the account."""
    for cid in ("BCK-04", "BCK-05"):
        assert "CIS-STORAGE" not in A.COMPLIANCE_MAP.get(cid, {})


def test_every_blocked_row_points_at_a_recorded_blocker():
    assert M.BLOCKERS, "BLOCKED rows exist and no blocker is recorded"
    for name, why in M.BLOCKERS.items():
        assert len(why) > 80, f"blocker {name} is not explained"


# ═════════════════════════════════════════════════════════════════════════════
# 3a. Pure decisions
# ═════════════════════════════════════════════════════════════════════════════
def test_ebs_encryption_none_is_a_real_value_and_is_the_finding():
    """NONE is a member of the API's own enum, which is why DRS-01 exists at all
    rather than being a hypothetical about AWS-managed keys."""
    p = S.replication_template_posture({"replicationConfigurationTemplateID": "t-1",
                                        "ebsEncryption": "NONE"})
    assert p["unencrypted"] and p["encryption_known"] and not p["cmk"]


def test_default_and_custom_encryption_are_both_encrypted():
    for value, cmk in (("DEFAULT", False), ("CUSTOM", True)):
        p = S.replication_template_posture({"ebsEncryption": value})
        assert not p["unencrypted"]
        assert p["cmk"] is cmk


def test_an_absent_encryption_field_is_unknown_not_unencrypted():
    """Absent is unknown. Reporting a template the SDK did not describe as an
    unencrypted one would be a finding about botocore, not about the estate."""
    p = S.replication_template_posture({"replicationConfigurationTemplateID": "t-1"})
    assert not p["encryption_known"] and not p["unencrypted"]


def test_public_routing_is_detected_and_private_is_not_a_finding():
    assert S.replication_template_posture({"dataPlaneRouting": "PUBLIC_IP"})["public_routing"]
    assert not S.replication_template_posture({"dataPlaneRouting": "PRIVATE_IP"})["public_routing"]
    assert not S.replication_template_posture({})["routing_known"]


def test_in_flight_replication_states_are_not_failures():
    """A server catching up is working, not broken. Failing INITIAL_SYNC would make
    every freshly-added server a finding for as long as the first sync takes."""
    for state in ("INITIATING", "INITIAL_SYNC", "BACKLOG", "CREATING_SNAPSHOT",
                  "RESCAN", "CONTINUOUS"):
        p = S.source_server_posture(
            {"dataReplicationInfo": {"dataReplicationState": state}})
        assert not p["unhealthy"], f"{state} should not be a failure"


def test_stopped_states_are_failures():
    for state in ("STOPPED", "PAUSED", "STALLED", "DISCONNECTED"):
        p = S.source_server_posture(
            {"dataReplicationInfo": {"dataReplicationState": state}})
        assert p["unhealthy"], f"{state} should be a failure"


def test_never_launched_and_failed_launch_are_told_apart():
    assert S.source_server_posture({"lastLaunchResult": "NOT_STARTED"})["never_launched"]
    assert S.source_server_posture({"lastLaunchResult": "FAILED"})["launch_failed"]
    ok = S.source_server_posture({"lastLaunchResult": "SUCCEEDED"})
    assert not ok["never_launched"] and not ok["launch_failed"]


def test_a_plan_rule_with_a_copy_action_is_told_from_one_without():
    plan = {"BackupPlan": {"BackupPlanName": "daily", "Rules": [
        {"RuleName": "local", "TargetBackupVaultName": "v"},
        {"RuleName": "offsite", "CopyActions": [{"DestinationBackupVaultArn": "arn"}]},
    ]}}
    c = S.backup_plan_copy_posture(plan)
    assert c["any_copy"] and c["with_copy"] == ("offsite",)
    assert c["without_copy"] == ("local",)


def test_a_plan_with_no_rules_is_unknown_rather_than_uncopied():
    assert not S.backup_plan_copy_posture({"BackupPlan": {"Rules": []}})["known"]


def test_vault_key_ownership_is_read_from_the_type_not_the_arn():
    """EncryptionKeyArn is populated for both kinds, so telling them apart by string
    shape would be exactly the guess aws_cis_storage exists to avoid."""
    owned = S.backup_vault_key_posture(
        {"BackupVaultName": "v", "EncryptionKeyType": "AWS_OWNED_KMS_KEY",
         "EncryptionKeyArn": "arn:aws:kms:us-east-1:123456789012:key/abc"})
    assert owned["aws_owned"] and owned["known"]
    cmk = S.backup_vault_key_posture(
        {"EncryptionKeyType": "CUSTOMER_MANAGED_KMS_KEY"})
    assert not cmk["aws_owned"]
    assert not S.backup_vault_key_posture({"BackupVaultName": "v"})["known"]


# ═════════════════════════════════════════════════════════════════════════════
# 3b. Driving tests
# ═════════════════════════════════════════════════════════════════════════════
def _drs(templates=(), servers=()):
    c = MagicMock()
    c.describe_replication_configuration_templates.return_value = {
        "items": list(templates)}
    c.describe_source_servers.return_value = {"items": list(servers)}
    s = make_scanner(sections=["DRS"])
    s.account = OWN
    s._clients[f"drs:{REGION}"] = c
    return s


def test_drs01_unencrypted_staging_area_fails():
    s = _drs(templates=[{"replicationConfigurationTemplateID": "t-1",
                         "ebsEncryption": "NONE",
                         "dataPlaneRouting": "PRIVATE_IP"}])
    s._check_drs()
    _renders(s, "DRS-01", "HIGH", contains="t-1")
    assert not _ids(s, "DRS-02", "FAIL")


def test_drs02_public_replication_routing_fails():
    s = _drs(templates=[{"replicationConfigurationTemplateID": "t-1",
                         "ebsEncryption": "CUSTOM",
                         "dataPlaneRouting": "PUBLIC_IP"}])
    s._check_drs()
    _renders(s, "DRS-02", "MEDIUM", contains="t-1")
    assert not _ids(s, "DRS-01", "FAIL")


def test_drs03_stalled_replication_fails():
    s = _drs(servers=[{"sourceServerID": "s-1",
                       "lastLaunchResult": "SUCCEEDED",
                       "dataReplicationInfo": {"dataReplicationState": "STALLED",
                                               "lagDuration": "PT9H"}}])
    s._check_drs()
    r = _renders(s, "DRS-03", "HIGH", contains="s-1")
    assert "PT9H" in r.message, "the lag is the operator's first question"


def test_drs03_passes_on_continuous_replication():
    s = _drs(servers=[{"sourceServerID": "s-1",
                       "lastLaunchResult": "SUCCEEDED",
                       "dataReplicationInfo": {"dataReplicationState": "CONTINUOUS"}}])
    s._check_drs()
    assert not _ids(s, "DRS-03", "FAIL")
    assert _ids(s, "DRS-03", "PASS")


def test_drs04_never_drilled_fails():
    s = _drs(servers=[{"sourceServerID": "s-1",
                       "lastLaunchResult": "NOT_STARTED",
                       "dataReplicationInfo": {"dataReplicationState": "CONTINUOUS"}}])
    s._check_drs()
    _renders(s, "DRS-04", "MEDIUM", contains="s-1")


def test_drs04_a_failed_drill_is_reported_differently_from_never_drilled():
    """Worse than untested: the one attempt on record did not work."""
    s = _drs(servers=[{"sourceServerID": "s-1",
                       "lastLaunchResult": "FAILED",
                       "dataReplicationInfo": {"dataReplicationState": "CONTINUOUS"}}])
    s._check_drs()
    r = _renders(s, "DRS-04", "MEDIUM")
    assert "FAILED" in r.message and "never been launched" not in r.message


def test_drs_says_nothing_about_an_account_that_does_not_use_it():
    s = _drs()
    s._check_drs()
    assert not [f for f in s.results if f.check_id.startswith("DRS-")]


def _backup(vaults=(), plans=(), plan_detail=None):
    from test_live_scanner import MockPaginator
    bk = MagicMock()
    bk.list_backup_vaults.return_value = {"BackupVaultList": list(vaults)}

    def paginator(op):
        if op == "list_backup_vaults":
            return MockPaginator("BackupVaultList", list(vaults))
        return MockPaginator("BackupPlansList", list(plans))

    bk.get_paginator.side_effect = paginator
    bk.list_backup_plans.return_value = {"BackupPlansList": list(plans)}
    bk.get_backup_plan.return_value = plan_detail or {}
    bk.get_backup_vault_access_policy.side_effect = Exception("ResourceNotFound")
    bk.describe_backup_vault.return_value = {
        "BackupVaultName": (vaults[0]["BackupVaultName"] if vaults else "v"),
        "EncryptionKeyType": "AWS_OWNED_KMS_KEY",
        "Locked": True, "LockDate": None}
    s = make_scanner(sections=["BACKUP"])
    s.account = OWN
    s._clients[f"backup:{REGION}"] = bk
    return s


def test_bck04_a_plan_that_never_copies_off_region_fails():
    s = _backup(
        vaults=[{"BackupVaultName": "prod", "NumberOfRecoveryPoints": 12}],
        plans=[{"BackupPlanId": "p-1", "BackupPlanName": "daily"}],
        plan_detail={"BackupPlan": {"BackupPlanName": "daily", "Rules": [
            {"RuleName": "nightly", "TargetBackupVaultName": "prod"}]}})
    s._check_backup()
    _renders(s, "BCK-04", "MEDIUM", contains="daily")


def test_bck04_passes_when_a_rule_copies_elsewhere():
    s = _backup(
        vaults=[{"BackupVaultName": "prod", "NumberOfRecoveryPoints": 12}],
        plans=[{"BackupPlanId": "p-1", "BackupPlanName": "daily"}],
        plan_detail={"BackupPlan": {"BackupPlanName": "daily", "Rules": [
            {"RuleName": "nightly", "TargetBackupVaultName": "prod",
             "CopyActions": [{"DestinationBackupVaultArn":
                              "arn:aws:backup:eu-west-1:123456789012:vault:dr"}]}]}})
    s._check_backup()
    assert not _ids(s, "BCK-04", "FAIL")
    assert _ids(s, "BCK-04", "PASS")


def test_bck05_an_aws_owned_vault_key_fails():
    s = _backup(vaults=[{"BackupVaultName": "prod", "NumberOfRecoveryPoints": 12}])
    s._check_backup()
    _renders(s, "BCK-05", "LOW", contains="prod")


def test_bck05_passes_on_a_customer_managed_key():
    s = _backup(vaults=[{"BackupVaultName": "prod", "NumberOfRecoveryPoints": 12}])
    s._clients[f"backup:{REGION}"].describe_backup_vault.return_value = {
        "BackupVaultName": "prod",
        "EncryptionKeyType": "CUSTOMER_MANAGED_KMS_KEY"}
    s._check_backup()
    assert not _ids(s, "BCK-05", "FAIL")
    assert _ids(s, "BCK-05", "PASS")


# ═════════════════════════════════════════════════════════════════════════════
# 4. The document
# ═════════════════════════════════════════════════════════════════════════════
def test_the_document_is_not_stale():
    proc = subprocess.run([sys.executable, GENERATOR, "--check"],
                          capture_output=True, text=True,
                          cwd=os.path.dirname(GENERATOR))
    assert proc.returncode == 0, (
        f"docs/CIS_STORAGE_BENCHMARK.md is stale:\n{proc.stdout}\n{proc.stderr}")


def test_the_document_names_its_generator_and_the_licence_position():
    with open(DOC, encoding="utf-8") as fh:
        text = fh.read()
    assert "scripts/cis_storage_benchmark.py" in text
    assert "may not be redistributed" in text


def test_the_document_carries_no_benchmark_prose():
    """The licence position is that recommendation NUMBERS are references and the
    document's own words are not ours to republish. These are phrases from the
    source's section headings; none may appear."""
    with open(DOC, encoding="utf-8") as fh:
        text = fh.read().lower()
    for phrase in ("profile applicability", "rationale statement",
                   "impact statement", "audit procedure:", "remediation procedure",
                   "ensure to create", "ensure creating"):
        assert phrase not in text, f"source prose leaked into the document: {phrase}"
