"""Pure decisions for the CIS AWS Storage Services checks: DRS and AWS Backup.

Mirrors `aws_cis_compute.py` and `aws_cis_db.py`: no boto3, no network, no clock, so
every branch is unit-testable without a client.

EVERY FIELD NAME AND ENUM BELOW COMES FROM THE PINNED BOTOCORE MODEL, read rather
than recalled. That is not ceremony -- the last two times this project guessed, it
shipped `SNSTopicArn` where MemoryDB returns `SnsTopicArn` (a check that fails every
cluster for the wrong reason) and declared `docdb:` IAM actions that do not exist.
The two enums that carry the weight here:

    drs DescribeReplicationConfigurationTemplates
        ebsEncryption      ['DEFAULT', 'CUSTOM', 'NONE']
        dataPlaneRouting   ['PRIVATE_IP', 'PUBLIC_IP']

    drs DescribeSourceServers
        lastLaunchResult   ['NOT_STARTED', 'PENDING', 'SUCCEEDED', 'FAILED']
        dataReplicationInfo.dataReplicationState
                           ['STOPPED', 'INITIATING', 'INITIAL_SYNC', 'BACKLOG',
                            'CREATING_SNAPSHOT', 'CONTINUOUS', 'PAUSED', 'RESCAN',
                            'STALLED', 'DISCONNECTED']

`NONE` being a real member of `ebsEncryption` is the reason DRS-01 exists: an
unencrypted staging area is a state the API can actually report, not a hypothetical.

ABSENT IS UNKNOWN, NOT FALSE. Every posture below reports a `known` flag and the
callers stay silent when it is False. A replication template whose encryption field
the SDK did not return is not an unencrypted template, and reporting it as one would
be a finding about the SDK rather than about the estate.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Sequence

__all__ = [
    "EBS_ENCRYPTION_NONE", "EBS_ENCRYPTION_DEFAULT", "EBS_ENCRYPTION_CUSTOM",
    "ROUTING_PUBLIC", "ROUTING_PRIVATE", "UNHEALTHY_REPLICATION_STATES",
    "LAUNCH_NEVER", "LAUNCH_FAILED", "AWS_OWNED_KEY",
    "replication_template_posture", "source_server_posture",
    "backup_plan_copy_posture", "backup_vault_key_posture",
]

EBS_ENCRYPTION_NONE = "NONE"
EBS_ENCRYPTION_DEFAULT = "DEFAULT"
EBS_ENCRYPTION_CUSTOM = "CUSTOM"

ROUTING_PUBLIC = "PUBLIC_IP"
ROUTING_PRIVATE = "PRIVATE_IP"

#: Replication states that mean data is NOT currently being protected. The in-flight
#: states (INITIATING, INITIAL_SYNC, BACKLOG, CREATING_SNAPSHOT, RESCAN) are
#: deliberately absent: a server catching up is working, not broken, and failing it
#: would make every freshly-added server a finding for as long as the first sync
#: takes.
UNHEALTHY_REPLICATION_STATES = frozenset({
    "STOPPED", "PAUSED", "STALLED", "DISCONNECTED",
})

LAUNCH_NEVER = "NOT_STARTED"
LAUNCH_FAILED = "FAILED"

AWS_OWNED_KEY = "AWS_OWNED_KMS_KEY"


def _d(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> Sequence[Any]:
    return value if isinstance(value, (list, tuple)) else ()


def replication_template_posture(template: Optional[dict]) -> Dict[str, Any]:
    """DRS-01 (staging volumes encrypted) and DRS-02 (replication stays private).

    The staging area is where a copy of every protected disk lives continuously. It
    is the one place in a DR setup that holds production data outside production, so
    `ebsEncryption` of NONE means the whole estate's data sits unencrypted in a
    subnet most people never look at.
    """
    t = _d(template)
    enc = t.get("ebsEncryption") or ""
    routing = t.get("dataPlaneRouting") or ""
    return {
        "id": t.get("replicationConfigurationTemplateID") or "",
        "encryption": enc,
        "encryption_known": bool(enc),
        "unencrypted": enc == EBS_ENCRYPTION_NONE,
        "cmk": enc == EBS_ENCRYPTION_CUSTOM,
        "key_arn": t.get("ebsEncryptionKeyArn") or "",
        "routing": routing,
        "routing_known": bool(routing),
        "public_routing": routing == ROUTING_PUBLIC,
        "staging_subnet": t.get("stagingAreaSubnetId") or "",
        "default_security_group": t.get("associateDefaultSecurityGroup") is True,
    }


def source_server_posture(server: Optional[dict]) -> Dict[str, Any]:
    """DRS-03 (replication healthy) and DRS-04 (recovery actually exercised)."""
    s = _d(server)
    info = _d(s.get("dataReplicationInfo"))
    raw_state = info.get("dataReplicationState")
    state = raw_state if isinstance(raw_state, str) else ""
    raw_launch = s.get("lastLaunchResult")
    launch = raw_launch if isinstance(raw_launch, str) else ""
    return {
        "id": s.get("sourceServerID") or "",
        "state": state,
        "state_known": bool(state),
        "unhealthy": state in UNHEALTHY_REPLICATION_STATES,
        "lag": info.get("lagDuration") or "",
        "launch_result": launch,
        "launch_known": bool(launch),
        "never_launched": launch == LAUNCH_NEVER,
        "launch_failed": launch == LAUNCH_FAILED,
        "agent_version": s.get("agentVersion") or "",
    }


def backup_plan_copy_posture(plan: Optional[dict]) -> Dict[str, Any]:
    """BCK-04 -- does any rule copy the recovery point somewhere else?

    A backup plan whose rules all write to a vault in the same account and region as
    the resource they protect survives an accidental deletion and nothing else. The
    region going away, or the account being compromised by someone who can also
    delete the vault, takes the backup with the original. `CopyActions` is the only
    field in the plan that says otherwise.
    """
    p = _d(_d(plan).get("BackupPlan")) or _d(plan)
    rules = _l(p.get("Rules"))
    with_copy, without_copy = [], []
    for rule in rules:
        r = _d(rule)
        name = r.get("RuleName") or r.get("RuleId") or "?"
        (with_copy if _l(r.get("CopyActions")) else without_copy).append(name)
    return {
        "name": p.get("BackupPlanName") or "",
        "rules": len(rules),
        "known": bool(rules),
        "with_copy": tuple(with_copy),
        "without_copy": tuple(without_copy),
        "any_copy": bool(with_copy),
    }


def backup_vault_key_posture(vault: Optional[dict]) -> Dict[str, Any]:
    """BCK-05 -- is the vault on a key this account administers?

    `EncryptionKeyType` is read in preference to inferring ownership from
    `EncryptionKeyArn`, because the ARN is populated for both kinds and telling them
    apart by string shape is exactly the sort of guess this module exists to avoid.
    """
    v = _d(vault)
    kind = v.get("EncryptionKeyType") or ""
    return {
        "name": v.get("BackupVaultName") or "",
        "key_type": kind,
        "known": bool(kind),
        "aws_owned": kind == AWS_OWNED_KEY,
        "key_arn": v.get("EncryptionKeyArn") or "",
        "recovery_points": v.get("NumberOfRecoveryPoints") or 0,
    }
