"""Every `aws <service> <verb>` we tell an operator to run must be a real command.

WHY A GUARD AND NOT A BANNED-LIST. `tests/test_finding_detail.py` already bans
`update-function-code-signing-config` by name -- but it reads only FINDING_DETAIL,
and REMEDIATION_MAP holds a SECOND, independently-written copy of most
remediations. So the Lambda fix landed in the map the guard watched, and the
other map shipped `aws lambda update-function-code-signing-config` regardless.
Naming bad tokens one at a time can only ever catch the mistakes already made,
in the one place someone thought to look.

This asks botocore instead. `xform_name` is the transform the AWS CLI itself
uses to turn an operation name into a command word, so the check is against the
shipped model rather than against anyone's memory of it -- the same rule the
scanner follows for IAM prefixes and field names.

What it found on the sweep that introduced it, out of 2,441 correct verbs:
  * LMB-06  `lambda update-function-code-signing-config` -> put-...      (REMEDIATION_MAP)
  * PCA-01  `acm-pca list-certificates` -- no such operation            (both maps)
  * IMI-01  `aws iotmanagedintegrations` -- that is the SIGNING name;
            the CLI command word is `iot-managed-integrations`          (both maps)
"""
from __future__ import annotations

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

botocore = pytest.importorskip("botocore")
import botocore.session                                         # noqa: E402
from botocore import xform_name                                 # noqa: E402

from engine import aws_finding_detail as D                      # noqa: E402
from engine.aws_live_scanner import REMEDIATION_MAP             # noqa: E402

_SESSION = botocore.session.get_session()
_AVAILABLE = set(_SESSION.get_available_services())

#: aws-cli command word -> botocore service name, where the two genuinely differ.
CLI_ALIASES = {
    "s3api": "s3",
    "configservice": "config",
    "deploy": "codedeploy",
    "codeguru-profiler": "codeguruprofiler",
}

#: CLI command words with no botocore service behind them at all.
NOT_API_COMMANDS = {
    "s3": "high-level file transfer wrapper (cp/sync/ls), not an API surface",
    "configure": "local credential/profile management",
    "ddb": "high-level DynamoDB wrapper",
    "help": "not a service",
    "history": "not a service",
}

#: `aws <svc> <verb>` pairs the CLI really does accept but botocore does not model.
#: These are CLI-side customizations: composite commands, or ones computed locally.
#: Each entry is a claim that the command exists -- keep the reason with it.
CLI_ONLY_COMMANDS = {
    ("logs", "tail"): "CLI-side live tail over FilterLogEvents/StartLiveTail",
    ("cloudtrail", "validate-logs"): "CLI-side digest-chain verification; no API op",
    ("rds", "generate-db-auth-token"): "computed locally by the CLI, signs no request",
    ("emr", "create-cluster"): "CLI customization wrapping RunJobFlow",
}

#: Flags the CLI accepts on every command, belonging to no operation's input shape.
GLOBAL_FLAGS = {
    "--region", "--profile", "--output", "--query", "--endpoint-url", "--no-verify-ssl",
    "--no-paginate", "--page-size", "--max-items", "--starting-token", "--debug",
    "--cli-input-json", "--generate-cli-skeleton", "--cli-read-timeout",
    "--cli-connect-timeout", "--color", "--no-cli-pager", "--cli-binary-format",
    "--ca-bundle", "--no-sign-request",
}

# `aws` must START a command word -- not appear inside a hostname. Without the
# lookbehind, `*.lambda-url.<region>.on.aws hostname that AWS resolves` in LMB-08
# parses as the command `aws hostname`.
_CMD = re.compile(r"(?<![.\w-])aws\s+([a-z0-9][a-z0-9-]*)\s+([a-z][a-z0-9-]*)")
# the flags trailing a command, up to the next `aws ` or end of sentence-ish text
_CMD_WITH_FLAGS = re.compile(
    r"(?<![.\w-])aws\s+([a-z0-9][a-z0-9-]*)\s+([a-z][a-z0-9-]*)((?:(?!(?<![.\w-])aws\s).)*)",
    re.S)
_FLAG = re.compile(r"(?<![\w-])--[a-z][a-z0-9-]*")

_FLAG_CACHE: dict[tuple[str, str], set[str] | None] = {}


def _flags_for(cli_word: str, verb: str):
    """The `--flags` `aws <cli_word> <verb>` accepts, or None if not resolvable."""
    key = (cli_word, verb)
    if key not in _FLAG_CACHE:
        service = CLI_ALIASES.get(cli_word, cli_word)
        got = None
        if service in _AVAILABLE:
            model = _SESSION.get_service_model(service)
            for op in model.operation_names:
                if xform_name(op).replace("_", "-") == verb:
                    shape = model.operation_model(op).input_shape
                    members = shape.members if shape is not None else {}
                    got = {"--" + xform_name(m).replace("_", "-") for m in members}
                    # the CLI synthesises a --no-X for BOOLEAN members only, so
                    # restrict the negations rather than pardoning --no-anything
                    got |= {"--no-" + xform_name(m).replace("_", "-")
                            for m, sh in members.items() if sh.type_name == "boolean"}
                    break
        _FLAG_CACHE[key] = got
    return _FLAG_CACHE[key]

_VERB_CACHE: dict[str, set[str] | None] = {}


def _verbs_for(cli_word: str):
    """The command words `aws <cli_word> ...` accepts, or None if unresolvable."""
    if cli_word not in _VERB_CACHE:
        service = CLI_ALIASES.get(cli_word, cli_word)
        if service not in _AVAILABLE:
            _VERB_CACHE[cli_word] = None
        else:
            model = _SESSION.get_service_model(service)
            _VERB_CACHE[cli_word] = {
                xform_name(op).replace("_", "-") for op in model.operation_names}
    return _VERB_CACHE[cli_word]


def _surfaces():
    """(where, check_id, text) for every operator-facing remediation string."""
    for cid, text in REMEDIATION_MAP.items():
        yield "REMEDIATION_MAP", cid, text or ""
    for cid, d in D.FINDING_DETAIL.items():
        yield "FINDING_DETAIL", cid, " ".join(
            [d.get("risk", ""), d.get("impact", "")] + list(d.get("steps", ())))


def _commands():
    for where, cid, text in _surfaces():
        for svc, verb in _CMD.findall(text):
            yield where, cid, svc, verb


def _commands_with_flags():
    """Same commands, each with the text that follows it up to the next `aws `."""
    for where, cid, text in _surfaces():
        for svc, verb, tail in _CMD_WITH_FLAGS.findall(text):
            yield where, cid, svc, verb, tail


# ── the guard ───────────────────────────────────────────────────────────────
def test_every_remediation_verb_is_a_real_command():
    """A remediation an operator pastes must not abort on an unknown command."""
    bad = sorted({(w, c, s, v) for w, c, s, v in _commands()
                  if s not in NOT_API_COMMANDS
                  and (s, v) not in CLI_ONLY_COMMANDS
                  and (_verbs_for(s) or set()) and v not in _verbs_for(s)})
    assert not bad, "invalid AWS CLI verbs in remediation text:\n" + "\n".join(
        f"  {w}/{c}: aws {s} {v}" for w, c, s, v in bad)


def test_every_remediation_names_a_service_the_cli_has():
    """`aws iotmanagedintegrations ...` was the SIGNING name. It is the right
    string for an IAM action and the wrong one for a command word, and nothing
    distinguished them because both were typed by hand."""
    unknown = sorted({(w, c, s) for w, c, s, _ in _commands()
                      if s not in NOT_API_COMMANDS and _verbs_for(s) is None})
    assert not unknown, "remediation text names services the AWS CLI has not:\n" + "\n".join(
        f"  {w}/{c}: aws {s}" for w, c, s in unknown)


#: (service, verb, flag) triples the sweep reports that are NOT defects.
#:
#: A RATCHET, NOT A PARDON. Two things land here and they are different:
#:
#:  * CLI CUSTOMIZATIONS -- flags the AWS CLI adds on top of the API shape
#:    (`ec2 authorize-security-group-ingress --port`, `lambda
#:    publish-layer-version --zip-file`, `iam create-virtual-mfa-device
#:    --outfile`). botocore does not model these, and the `awscli` package that
#:    does is far too heavy to make a test dependency, so they cannot be
#:    resolved mechanically here.
#:  * PROSE -- a flag named in the sentence AFTER a command, which the tail
#:    regex cannot tell from an argument to it. LSAIL-03 is the sharp case: it
#:    names `--add-on-request` precisely to say it is NOT the path.
#:
#: The point is the closed set. A NEW unknown flag fails, which is what catches
#: the next OSR-02; nothing on this list is asserted to be correct.
KNOWN_UNRESOLVED_FLAGS = {
    # CLI customizations over the API shape
    ("ec2", "authorize-security-group-ingress", "--cidr"),
    ("ec2", "authorize-security-group-ingress", "--port"),
    ("ec2", "authorize-security-group-ingress", "--protocol"),
    ("ec2", "revoke-security-group-ingress", "--cidr"),
    ("ec2", "revoke-security-group-ingress", "--port"),
    ("ec2", "revoke-security-group-ingress", "--protocol"),
    ("ec2", "revoke-security-group-ingress", "--source-group"),
    ("ec2", "create-network-acl-entry", "--ingress"),
    ("ec2", "delete-network-acl-entry", "--ingress"),
    ("ec2", "replace-network-acl-entry", "--ingress"),
    ("ec2", "delete-volume", "--encrypted"),
    # AttributeBooleanValue is a STRUCTURE in the model; the CLI flattens these
    # to --x / --no-x, which is why the boolean-only negation rule misses them
    ("ec2", "modify-subnet-attribute", "--no-map-public-ip-on-launch"),
    ("iam", "create-virtual-mfa-device", "--bootstrap-method"),
    ("iam", "create-virtual-mfa-device", "--outfile"),
    ("lambda", "publish-layer-version", "--zip-file"),
    ("sns", "subscribe", "--notification-endpoint"),
    ("eks", "update-cluster-version", "--kubernetes-version"),
    ("kms", "create-key", "--encryption-key-arn"),
    # prose after the command, not arguments to it
    ("account", "list-regions", "--all-regions"),
    ("bedrock-agentcore-control", "delete-code-interpreter", "--browser-id"),
    ("bedrock-agentcore-control", "delete-registry-record", "--registry-identifier"),
    ("bedrock-agentcore-control", "get-registry-record", "--registry-identifier"),
    ("bedrock-agentcore-control", "get-gateway-target", "--lookup-attributes"),
    ("bedrock-agentcore-control", "get-gateway-target", "--state"),
    ("bedrock-agentcore-control", "submit-registry-record-for-approval", "--registry-identifier"),
    ("cloudfront", "update-distribution", "--script"),
    ("cloudfront", "update-distribution", "--web-acl-id"),
    ("cloudtrail", "lookup-events", "--values-to-add"),
    ("dynamodb", "update-table", "--kms-key-id"),
    ("eks", "associate-encryption-config", "--all-namespaces"),
    ("eks", "describe-cluster", "--overwrite"),
    ("eks", "disassociate-access-policy", "--access-scope"),
    ("eks", "list-associated-access-policies", "--access-scope"),
    ("elasticache", "increase-replica-count", "--multi-az-enabled"),
    ("elb", "set-load-balancer-policies-of-listener", "--script"),
    ("elbv2", "modify-listener", "--script"),
    ("lambda", "list-functions", "--side-scan-lambda"),   # an OverWatch flag, in prose
    ("lightsail", "disable-add-on", "--add-on-request"),  # named to say it is NOT the path
    ("memorydb", "describe-engine-versions", "--maintenance-window"),
    ("rds", "modify-db-cluster-parameter-group", "--ssl-mode"),
    ("rds", "modify-db-parameter-group", "--ssl-mode"),
    ("redshift", "get-cluster-credentials", "--master-username"),
    ("redshift-serverless", "get-workgroup", "--no-publicly-accessible"),
    ("sagemaker", "describe-domain", "--app-network-access-type"),
    ("sagemaker", "describe-domain", "--kms-key-id"),
    ("sagemaker", "describe-endpoint", "--kms-key-id"),
    ("sagemaker", "describe-notebook-instance", "--direct-internet-access"),
    ("sagemaker", "describe-notebook-instance", "--kms-key-id"),
    ("sagemaker", "describe-notebook-instance", "--root-access"),
    ("signer", "put-signing-profile", "--id"),
    ("signer", "put-signing-profile", "--plugin"),
    ("ssm", "list-inventory-entries", "--now"),
    ("ssm", "send-command", "--now"),
}


def _unknown_flags():
    for where, cid, svc, verb, tail in _commands_with_flags():
        if svc in NOT_API_COMMANDS or (svc, verb) in CLI_ONLY_COMMANDS:
            continue
        known = _flags_for(svc, verb)
        if not known:
            continue                       # unresolvable command: the verb tests own it
        for flag in _FLAG.findall(tail):
            if flag not in known and flag not in GLOBAL_FLAGS:
                yield where, cid, svc, verb, flag


def test_no_new_flag_appears_that_the_command_does_not_accept():
    """OSR-02 IS WHY THIS EXISTS. `--encrypt-at-rest-options` (the OpenSearch flag
    is `--encryption-at-rest-options`) was banned by name in test_finding_detail
    and fixed there -- and REMEDIATION_MAP kept the invalid flag, one line away
    from OSR-03 which spells it correctly. A verb-only guard sails straight past
    it: the verb `update-domain-config` is perfectly real.

    Eight more came out of the same sweep, and they were not typos -- they were
    remediations that could not work:
      SM-01/SM-04/AISPM-03/AIPATH-01  update-notebook-instance --direct-internet-access
                                      / --subnet-id: both fixed at CREATION, so the
                                      advertised one-command fix always fails
      AGT-03                          --server-side-encryption-configuration belongs to
                                      the data source, not the knowledge base
      DOCDB-07                        --no-publicly-accessible: DocumentDB has no such
                                      setting (RDS and Neptune do -- hence the copy)
      DOCDB-02/NEP-01                 restore-...-from-snapshot --storage-encrypted:
                                      the key is what encrypts a restore
      MDB-05                          --auto-minor-version-upgrade: create-time only
      APS-05                          --disable-imds-v1 -> --disable-imdsv1
    """
    bad = sorted({f"  {w}/{c}: aws {s} {v} {f}"
                  for w, c, s, v, f in _unknown_flags()
                  if (s, v, f) not in KNOWN_UNRESOLVED_FLAGS})
    assert not bad, ("flags the command does not accept:\n" + "\n".join(bad)
                     + "\n\nIf this is an AWS CLI customization botocore does not model, "
                       "add it to KNOWN_UNRESOLVED_FLAGS with a reason.")


def test_the_unresolved_list_does_not_rot():
    """An allowlist nobody prunes stops being a ratchet. An entry that no longer
    appears has been fixed or reworded, and must be dropped so the set keeps
    meaning 'everything we could not resolve'."""
    live = {(s, v, f) for _w, _c, s, v, f in _unknown_flags()}
    stale = sorted(KNOWN_UNRESOLVED_FLAGS - live)
    assert not stale, "KNOWN_UNRESOLVED_FLAGS entries nothing produces any more:\n" + "\n".join(
        f"  aws {s} {v} {f}" for s, v, f in stale)


def test_the_flag_sweep_reaches_a_real_number_of_flags():
    """Same reason as the command sweep: a regex that quietly stopped matching
    would turn this whole module into a pass-by-default."""
    n = sum(len(_FLAG.findall(tail))
            for *_ignored, tail in _commands_with_flags())
    assert n > 1500, f"only {n} flags parsed -- the regex broke"


def test_a_wrong_flag_on_a_real_verb_is_caught():
    """The exact OSR-02 shape, as data -- a valid command with one invalid flag."""
    known = _flags_for("opensearch", "update-domain-config")
    assert known and "--encryption-at-rest-options" in known
    assert "--encrypt-at-rest-options" not in known


# NOT TESTED: that the two maps name the SAME command for a check. 559 checks
# appear in both and 15 share no command at all -- every one of them correctly,
# because the one-liner gives the fix (`aws sagemaker update-notebook-instance`)
# while the steps give the surrounding procedure (`create-` / `delete-`). There
# is no invariant there, only a temptation to write an assertion that cannot
# fail. The guards below are the ones with teeth.


# ── the guard must actually be looking at something ─────────────────────────
def test_the_sweep_reaches_both_maps_and_a_real_number_of_commands():
    """A guard whose regex silently stopped matching would pass forever."""
    seen = list(_commands())
    wheres = {w for w, *_ in seen}
    assert wheres == {"REMEDIATION_MAP", "FINDING_DETAIL"}, wheres
    assert len(seen) > 2000, f"only {len(seen)} commands parsed -- the regex broke"


def test_the_known_bad_verbs_would_still_be_caught():
    """The three defects this module was written for, as data. If any becomes
    valid in a future botocore, this fails and tells us to drop it."""
    for svc, verb in (("lambda", "update-function-code-signing-config"),
                      ("acm-pca", "list-certificates")):
        verbs = _verbs_for(svc)
        assert verbs is not None and verb not in verbs, (
            f"aws {svc} {verb} is now a real command -- retire it from this list")
    assert _verbs_for("iotmanagedintegrations") is None, (
        "the signing name resolves as a CLI command word now")
    assert _verbs_for("iot-managed-integrations"), "the real service word must resolve"


def test_the_replacements_we_shipped_are_real():
    """Fixing a wrong verb by guessing another wrong verb is the easy mistake."""
    assert "put-function-code-signing-config" in _verbs_for("lambda")
    assert "create-certificate-authority-audit-report" in _verbs_for("acm-pca")
    assert "put-default-encryption-configuration" in _verbs_for("iot-managed-integrations")


@pytest.mark.parametrize("svc,verb", sorted(CLI_ONLY_COMMANDS))
def test_the_cli_only_allowlist_stays_justified(svc, verb):
    """Each entry claims 'the CLI has this but botocore does not model it'. If
    botocore starts modelling it, the exemption is no longer needed and the
    entry should go -- an allowlist nobody prunes is how real breakage hides."""
    verbs = _verbs_for(svc)
    assert verbs is None or verb not in verbs, (
        f"aws {svc} {verb} is modelled by botocore now; drop it from CLI_ONLY_COMMANDS")
    assert CLI_ONLY_COMMANDS[(svc, verb)].strip(), "an exemption needs a reason"
