"""The IaC scanner's rules, proven to fire against deliberately-bad fixtures.

WHAT WAS TRUE BEFORE THIS FILE. `engine/aws_offline_scanner.py` is a separately
shipped product — the pre-deploy IaC gate that runs in customers' CI — with 148 rules
in 2,460 lines and ten tests. Those ten tests say so themselves: "Deterministic —
findings are injected, so it never depends on rule content." That is the right way to
test the CI gate and the SARIF emitter, and it means not one of the 148 rules was
exercised by anything.

Worse, the two halves were not equally neglected:

  * `tests/samples/vulnerable_network.tf` existed, was clearly used once to generate
    the sample findings beside it, and NO TEST REFERENCED IT. It fires 32 of the 59
    Terraform rules.
  * The 89 CloudFormation rules — the larger half — had no fixture at all, so none of
    them had ever produced a finding outside a customer's own repository.

A rule that never fires in CI is indistinguishable from a clean template. For a
pre-deploy gate that is the whole failure: the build goes green and the finding was
never possible.

WHAT THE FIXTURES COST TO WRITE, recorded because it is the useful part. Six rules
could not be reached by any single resource, because the handler takes an if/elif or
checks the opposite branch — a policy with a wildcard action AND a wildcard resource
is reported as `AWS-IAM-003`, so `AWS-IAM-004` needs a second policy with a specific
resource. Four more needed exact values a plausible-looking guess missed:
`MinimumProtocolVersion: SSLv3` reads as worse than `TLSv1` and is not on the
deprecated list the handler checks; a flow log with `TrafficType: REJECT` passes,
because the rule fires on ACCEPT-only. Each of those was a fixture that looked
obviously insecure and proved nothing.

THE RATCHET WORKS IN BOTH DIRECTIONS. `MINIMUM_RULES_FIRED` can only rise, and
`UNFIRED_TERRAFORM` can only shrink; a new rule arrives unfired, so shipping one
without a fixture that reaches it fails the build.
"""
from __future__ import annotations

import io
import json
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "tests", "samples")

from engine import aws_offline_scanner as sc  # noqa: E402

TF_FIXTURE = os.path.join(SAMPLES, "vulnerable_network.tf")
CF_FIXTURE = os.path.join(SAMPLES, "vulnerable_cloudformation.yaml")

#: Floor, not a target. Raise it when a fixture reaches further; never lower it.
MINIMUM_RULES_FIRED = 121

#: The remaining Terraform rules no fixture reaches. This list can only shrink.
#: They are regex rules in the `_sast_scan` table, so closing one means adding the
#: matching block to vulnerable_network.tf.
UNFIRED_TERRAFORM = {
    "AWS-APIGW-TF-001", "AWS-BR-TF-001", "AWS-CW-TF-001", "AWS-CW-TF-002",
    "AWS-CW-TF-003", "AWS-DDB-TF-001", "AWS-EB-TF-001", "AWS-EB-TF-002",
    "AWS-EBS-TF-001", "AWS-ECS-TF-002", "AWS-GD-TF-001", "AWS-IAM-TF-001",
    "AWS-IAM-TF-002", "AWS-IAM-TF-003", "AWS-IAM-TF-004", "AWS-LAM-TF-001",
    "AWS-OS-TF-002", "AWS-RS-TF-001", "AWS-RS-TF-002", "AWS-S3-TF-001",
    "AWS-SFN-TF-001", "AWS-SFN-TF-002", "AWS-SG-TF-002", "AWS-SG-TF-003",
    "AWS-SM-TF-002", "AWS-VPC-TF-001", "AWS-WAF-TF-001",
}

RULE_RE = re.compile(r'"(AWS-[A-Z0-9]+(?:-TF)?-[0-9]{3})"')


def all_rules() -> set:
    src = io.open(os.path.join(ROOT, "engine", "aws_offline_scanner.py"),
                  encoding="utf-8", errors="replace").read()
    return set(RULE_RE.findall(src))


def scan(*paths) -> set:
    s = sc.AWSIaCScanner()
    for p in paths:
        s.scan_path(p)
    return {f.rule_id for f in s.findings}


@pytest.fixture(scope="module")
def fired():
    return scan(TF_FIXTURE, CF_FIXTURE)


# ── the fixtures must actually be reached ──────────────────────────────────

def test_both_fixtures_exist_and_are_scanned():
    """The Terraform fixture existed for the life of the project and no test opened
    it. A fixture nothing reads is a fixture nothing proves."""
    assert os.path.exists(TF_FIXTURE)
    assert os.path.exists(CF_FIXTURE)
    assert scan(TF_FIXTURE), "the terraform fixture produced no findings at all"
    assert scan(CF_FIXTURE), "the cloudformation fixture produced no findings at all"


# ── the ratchet ────────────────────────────────────────────────────────────

def test_rule_coverage_can_only_grow(fired):
    covered = len(fired & all_rules())
    assert covered >= MINIMUM_RULES_FIRED, (
        "%d rules fire, the floor is %d. A rule stopped firing, or a new one shipped "
        "with no fixture reaching it." % (covered, MINIMUM_RULES_FIRED))


def test_the_floor_is_not_stale(fired):
    """A floor left far below the real number stops being a ratchet. Raise it when a
    fixture reaches further, in the same commit."""
    covered = len(fired & all_rules())
    assert covered - MINIMUM_RULES_FIRED <= 3, (
        "%d rules fire but the floor is only %d; raise it" % (covered,
                                                              MINIMUM_RULES_FIRED))


def test_every_cloudformation_rule_fires(fired):
    """The half that had no fixture at all. All 89 are now reachable, and this keeps
    it that way — a new CFN rule must arrive with the resource that trips it."""
    cfn = {r for r in all_rules() if "-TF-" not in r}
    missing = sorted(cfn - fired)
    assert not missing, (
        "%d CloudFormation rule(s) no longer fire: %s" % (len(missing), missing))


def test_the_unfired_terraform_list_is_exact(fired):
    """Both halves of the ratchet. An entry that now fires must be removed (or the
    list rots into fiction); a rule that stops firing must be added deliberately,
    not silently."""
    tf = {r for r in all_rules() if "-TF-" in r}
    unfired = tf - fired
    fixed = sorted(UNFIRED_TERRAFORM - unfired)
    broken = sorted(unfired - UNFIRED_TERRAFORM)
    assert not fixed, "%s now fire and should leave UNFIRED_TERRAFORM" % (fixed,)
    assert not broken, (
        "%s stopped firing. Add a fixture that reaches them rather than listing "
        "them here." % (broken,))


def test_every_listed_rule_still_exists():
    """Deleting a rule without pruning the list leaves it describing rules that are
    gone."""
    gone = sorted(UNFIRED_TERRAFORM - all_rules())
    assert not gone, "%s named in UNFIRED_TERRAFORM but no longer defined" % (gone,)


# ── the fixture is a fixture, not a deployable ─────────────────────────────

def test_the_cloudformation_fixture_warns_against_deployment():
    """It is a working template full of public buckets and wildcard IAM. Somebody
    will eventually open it wondering what it is."""
    text = io.open(CF_FIXTURE, encoding="utf-8").read()
    assert "DO NOT DEPLOY" in text.upper()
    assert "TESTING ONLY" in text.upper()


# ── the committed sample output must still describe a real run ─────────────

def test_the_sample_findings_file_matches_a_live_scan():
    """`vulnerable_network_findings.json` ships beside the fixture as an example of
    the scanner's output. It was generated once; nothing checked it since. A sample
    that no longer matches the scanner misleads anyone reading it to learn the
    format."""
    p = os.path.join(SAMPLES, "vulnerable_network_findings.json")
    doc = json.load(io.open(p, encoding="utf-8"))
    rows = doc["findings"]
    # The serialised key is `id`; `rule_id` is the attribute name on Finding. Reading
    # the wrong one yields an empty set, which compares unequal and looks like drift
    # rather than a broken test.
    committed = {r["id"] for r in rows}
    assert committed, "the sample file parsed to no rule ids at all"
    assert committed == scan(TF_FIXTURE), (
        "the committed sample no longer matches what the scanner produces; "
        "regenerate it or explain the difference")
