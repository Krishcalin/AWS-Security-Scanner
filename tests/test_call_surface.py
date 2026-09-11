"""The call surface: can the role we ship actually make the calls the engine makes?

THE FAILURE THIS CLOSES. `deploy/cnapp-scanner-role.yaml` names the IAM actions a
customer must approve, and until now it named 124 while the engine could issue 295.
The other 171 were assumed to arrive via the SecurityAudit and ViewOnlyAccess
managed policies. Mostly they do. But nothing checked, AWS revises managed policies
without announcing it, and the assumption was already wrong: six `drs:` and
`backup:` reads shipped in a release with no grant in any policy, because Elastic
Disaster Recovery postdates SecurityAudit entirely.

That failure is invisible from inside. A denied call becomes a coverage note, the
scan completes, the console renders, and the section simply has nothing in it --
which looks exactly like an account with nothing wrong. The role file's own comment
is the standard this module enforces: *"a check that silently degrades to a coverage
note in every real deployment is worse than one that asks for the grant it needs."*

WHY A TEST AND NOT A REVIEW. The surface is derived from the source by AST, so it
moves whenever anyone adds a call. A reviewer cannot be expected to notice that a
new `describe_*` in an 11,000-line scanner needs a line in a YAML file two
directories away. The build can.

This asks "may the role make this call". It does NOT ask "which check needs it" --
that is `aws_perm_ledger`, which is hand-authored against call sites and answers a
harder question for a smaller set.
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

yaml = pytest.importorskip("yaml")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import gen_call_surface as G                                        # noqa: E402
import call_surface_baseline as S                                   # noqa: E402

CFN = os.path.join(ROOT, "deploy", "cnapp-scanner-role.yaml")

#: An inline role policy caps here. Exceeding it fails role creation at onboarding --
#: the worst possible moment to find out.
INLINE_LIMIT = 10240

#: Reads that would return workload DATA rather than configuration. These are why
#: the role attaches SecurityAudit + ViewOnlyAccess instead of ReadOnlyAccess, and
#: none may ever appear in a policy this repository ships.
DATA_READS = {
    "s3:getobject", "dynamodb:getitem", "dynamodb:query", "dynamodb:scan",
    "dynamodb:batchgetitem", "sqs:receivemessage", "secretsmanager:getsecretvalue",
    "ssm:getparameter", "ssm:getparameters", "kinesis:getrecords",
    "logs:getlogevents", "logs:filterlogevents",
}


class _CfnLoader(yaml.SafeLoader):
    pass


_CfnLoader.add_multi_constructor("!", lambda l, s, n: (
    l.construct_scalar(n) if isinstance(n, yaml.ScalarNode)
    else l.construct_sequence(n) if isinstance(n, yaml.SequenceNode)
    else l.construct_mapping(n)))


def _policies():
    with io.open(CFN, encoding="utf-8") as fh:
        doc = yaml.load(fh, Loader=_CfnLoader)
    return doc["Resources"]["CnappScannerRole"]["Properties"]["Policies"]


def _always_on_actions():
    out = set()
    for pol in _policies():
        for s in pol["PolicyDocument"]["Statement"]:
            act = s["Action"]
            out |= set(act if isinstance(act, list) else [act])
    return out


# ═════════════════════════════════════════════════════════════════════════════
# The load-bearing assertion
# ═════════════════════════════════════════════════════════════════════════════
def test_the_role_grants_every_call_the_engine_can_make():
    """Add a boto3 call and this fails until the role names the action.

    Deliberately computed from the source rather than from the committed
    inventory: comparing the inventory to the role would pass happily while both
    were stale. The engine is the authority on what the engine calls."""
    surface = G.compute()
    active, optin = G.role_actions()
    named = active | optin
    missing = sorted(a for a in surface if a not in named)
    assert not missing, (
        f"{len(missing)} action(s) the engine can call are granted by NO policy in "
        f"deploy/cnapp-scanner-role.yaml: {missing}. Every one of these becomes an "
        f"AccessDenied in a real account, and a denied read renders as an empty "
        f"section that is indistinguishable from a clean one. Add them to "
        f"CnappScannerServiceReads, or to an opt-in block if the grant should be a "
        f"customer decision.")


def test_the_committed_inventory_is_current():
    """The generated module must match what the generator produces today."""
    proc = subprocess.run([sys.executable, "scripts/gen_call_surface.py", "--check"],
                          capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == 0, (
        f"engine/aws_call_surface.py is stale. Run "
        f"`python scripts/gen_call_surface.py --update` and review the diff -- a "
        f"widened call surface is a decision.\n{proc.stdout}\n{proc.stderr}")


def test_the_inventory_and_a_live_derivation_agree():
    assert dict(S.CALL_SURFACE) == G.compute()


# ═════════════════════════════════════════════════════════════════════════════
# The charter
# ═════════════════════════════════════════════════════════════════════════════
def test_every_reachable_action_is_a_read():
    """read-only-of-CONFIG, asserted over what the code can actually call rather
    than over what somebody declared."""
    bad = sorted(a for a in S.CALL_SURFACE
                 if not a.split(":", 1)[1].startswith(G.READ_VERBS))
    assert not bad, f"non-read actions are reachable: {bad}"


def test_no_policy_we_ship_grants_a_workload_data_read():
    """The reason ReadOnlyAccess is not attached. Config reads describe a bucket;
    these read what is IN it."""
    granted = {a.lower() for a in _always_on_actions()}
    assert not (granted & DATA_READS), (
        f"the role grants workload-data reads: {sorted(granted & DATA_READS)}")


def test_no_wildcard_action_smuggles_in_a_data_read():
    """`s3:Get*` would grant s3:GetObject while reading as a config grant -- the
    exact over-grant that made naming 177 actions preferable to five wildcards."""
    wild = sorted(a for a in _always_on_actions() if a.endswith("*"))
    assert not wild, (
        f"wildcard actions in the shipped role: {wild}. A verb wildcard over these "
        f"services would grant ~2,590 actions beyond what the engine calls, "
        f"including s3:GetObject. Name the actions instead.")


# ═════════════════════════════════════════════════════════════════════════════
# The IAM-prefix trap, now closed for every service at once
# ═════════════════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("action", sorted(S.CALL_SURFACE))
def test_every_action_uses_a_real_iam_prefix(action):
    """A boto3 CLIENT name in place of an IAM prefix grants nothing and reads
    correctly. Six have been caught by hand in this repository; this catches the
    seventh across all 105 services without anyone noticing it."""
    prefix = action.split(":", 1)[0]
    assert prefix in set(G.PREFIX.values()), (
        f"{action}: {prefix!r} is not an IAM prefix botocore knows")


@pytest.mark.parametrize("client,iam", [
    ("sso-admin", "sso"), ("amp", "aps"),
    ("bedrock-agentcore-control", "bedrock-agentcore"),
    ("emr", "elasticmapreduce"), ("cloudhsmv2", "cloudhsm"),
    ("opensearch", "es"), ("elbv2", "elasticloadbalancing"),
    ("cloudwatch", "monitoring"), ("efs", "elasticfilesystem"),
])
def test_the_known_client_name_traps_resolve_correctly(client, iam):
    """Pinned so the resolver keeps answering the question it was built for."""
    assert G.PREFIX.get(client) == iam, (
        f"botocore maps client {client!r} to {G.PREFIX.get(client)!r}, expected {iam!r}")


def test_the_surface_actually_contains_the_trapped_spellings():
    """The guard above is worthless if no call exercises it. These are the right
    spellings for services the engine really does read."""
    prefixes = {a.split(":", 1)[0] for a in S.CALL_SURFACE}
    for real in ("elasticloadbalancing", "elasticfilesystem", "es", "monitoring",
                 "elasticmapreduce", "sso"):
        assert real in prefixes, f"{real} vanished from the surface"
    for wrong in ("elbv2", "efs", "opensearch", "cloudwatch", "emr", "sso-admin"):
        assert wrong not in prefixes, (
            f"{wrong} is a boto3 client name, not an IAM prefix -- a policy written "
            f"with it grants nothing")


# ═════════════════════════════════════════════════════════════════════════════
# Policy mechanics: it has to be deployable
# ═════════════════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("index", range(len(_policies())))
def test_each_inline_policy_fits_with_headroom(index):
    """An oversized inline policy fails role creation at onboarding. The split into
    two documents happened here: the combined set renders to ~9,300 of 10,240, which
    left a growing catalogue about thirty checks of room."""
    pol = _policies()[index]
    size = len(json.dumps(pol["PolicyDocument"], separators=(",", ":")))
    assert size <= INLINE_LIMIT * 0.8, (
        f"{pol['PolicyName']} is {size:,} chars, over 80% of the {INLINE_LIMIT:,} "
        f"inline-policy limit. Split it before it fails a customer's stack create.")


#: Grants issued through a seam the AST walk does not resolve. Each is a real call.
_RESOLVED_ELSEWHERE = {
    # aws_effperm builds its own client for the CIEM last-accessed reads.
    "iam:GenerateServiceLastAccessedDetails",
    "iam:GetServiceLastAccessedDetails",
    "iam:GetServiceLastAccessedDetailsWithEntities",
    "access-analyzer:ValidatePolicy",
}

#: Grants NOTHING calls. Recorded rather than removed, and recorded rather than
#: quietly exempted -- an over-grant a reviewer cannot see is the same species of
#: problem as a missing one, just pointing the other way. Each is one letter from a
#: call the engine does make, which is how they got here:
#:
#:   cloudformation:ListStacks       -- the engine calls DescribeStacks
#:   codeartifact:ListRepositories   -- the engine calls ListRepositoriesInDomain
#:   ec2:GetEbsDefaultKmsKeyId       -- the engine calls GetEbsEncryptionByDefault
#:   ec2:GetSnapshotBlockPublicAccessState -- no caller at all
#:
#: They are left in place for now because this analyser had two blind spots found in
#: a single afternoon (helper parameters, and getattr dispatch), so "no caller
#: visible" earns less confidence than it looks like it should. Removing a grant is
#: safe only once you are sure nothing needs it.
KNOWN_OVER_GRANTS = {
    "cloudformation:ListStacks",
    "codeartifact:ListRepositories",
    "ec2:GetEbsDefaultKmsKeyId",
    "ec2:GetSnapshotBlockPublicAccessState",
}


def test_no_new_grant_is_added_that_nothing_calls():
    """The converse direction, and the one that found the analyser's blind spots.

    Asserting it caught twenty-two grants with no visible caller. Eighteen were
    real calls this walk could not see -- clients passed to helpers, and operations
    dispatched by name out of a table -- and fixing those raised the surface from
    295 actions to 352. The remaining four are genuine over-grants, pinned above."""
    unused = sorted(a for a in _always_on_actions()
                    if a not in S.CALL_SURFACE
                    and a not in _RESOLVED_ELSEWHERE
                    and a not in KNOWN_OVER_GRANTS)
    assert not unused, (
        f"the role asks for {len(unused)} action(s) nothing calls: {unused}. Either "
        f"the engine lost a call and the grant should go, or the deriver cannot see "
        f"a call shape and scripts/gen_call_surface.py needs to learn it. Check which "
        f"before adding anything to KNOWN_OVER_GRANTS.")


def test_the_recorded_over_grants_are_still_over_grants():
    """So the list shrinks when someone builds the check that needed one, instead of
    becoming a permanent excuse."""
    stale = sorted(a for a in KNOWN_OVER_GRANTS if a in S.CALL_SURFACE)
    assert not stale, (
        f"{stale} now HAVE callers -- remove them from KNOWN_OVER_GRANTS")
    absent = sorted(a for a in KNOWN_OVER_GRANTS if a not in _always_on_actions())
    assert not absent, (
        f"{absent} are no longer granted by the role -- remove them from "
        f"KNOWN_OVER_GRANTS, the over-grant is fixed")
