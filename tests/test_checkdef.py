"""The check-declaration registry.

`test_check_maps_lockstep` already catches a half-declared check, and it is a good test.
But it catches it AFTERWARDS. A `CheckDef` cannot be constructed unless every projection
is present and well-formed, which moves the same invariant from test-time to
definition-time: the failure stops being "someone forgot the detail page" and becomes
"this does not import".

The collision guard is the load-bearing part. Merging by `dict.update` bypasses the
duplicate-key ratchet, which parses dict LITERALS as source and cannot see a registry
merge — so `merge_*` refuses to overwrite an existing id. That is the SEG-01 defect
caught structurally rather than by a test that happened to exist.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_checkdef as C

RISK = ("A sufficiently long risk narrative, because the detail page is what a reviewer "
        "reads when deciding whether a finding is real, and one sentence has never been "
        "enough to make that call. This padding exists so the fixture clears the "
        "minimum length the dataclass enforces on the risk field for every check.")


def mk(cid="TEST-01", **kw):
    base = dict(
        id=cid, section="TEST", severity="HIGH",
        compliance={"PCI-DSS": "1.1", "HIPAA": "164.312(a)", "SOC2": "CC6.1",
                    "NIST": "AC-3"},
        remediation="Fix it: aws ec2 describe-instances --instance-ids <ID>",
        risk=RISK, impact="Something bad becomes possible.",
        steps=("Do the first thing.", "Verify it took effect."),
        permissions=(C.Perm("ec2:DescribeInstances",
                            "read instance configuration to grade exposure posture"),),
    )
    base.update(kw)
    return C.CheckDef(**base)


@pytest.fixture(autouse=True)
def _clean():
    """Isolate each test WITHOUT destroying the real registrations.

    An earlier version called C.reset() directly. The registry is module-global and
    batch-2's checks register at import of aws_extsvc2 -- which happens once per
    session -- so clearing it wiped them for every test that ran afterwards. Snapshot
    and restore instead: the same isolation, none of the collateral damage."""
    saved = dict(C.REGISTRY)
    C.REGISTRY.clear()
    yield
    C.REGISTRY.clear()
    C.REGISTRY.update(saved)


# ── a well-formed declaration ───────────────────────────────────────────────
def test_a_complete_declaration_constructs():
    assert mk().id == "TEST-01"


def test_registering_projects_into_every_map():
    """The whole point: declare once, derive five."""
    C.register(mk())
    assert C.severities() == {"TEST-01": "HIGH"}
    assert C.compliance()["TEST-01"]["NIST"] == "AC-3"
    assert "aws " in C.remediation()["TEST-01"]
    assert set(C.detail()["TEST-01"]) == {"risk", "impact", "steps"}
    assert C.permissions()["TEST-01"][0].action == "ec2:DescribeInstances"


def test_a_check_with_no_permissions_is_absent_from_the_ledger_projection():
    """Not every check needs a grant the shipped role lacks."""
    C.register(mk(permissions=()))
    assert "TEST-01" not in C.permissions()
    assert "TEST-01" in C.severities()


# ── every projection is mandatory at construction ───────────────────────────
def test_an_unknown_severity_is_refused():
    with pytest.raises(ValueError, match="severity"):
        mk(severity="SEVERE")


@pytest.mark.parametrize("framework", C.FRAMEWORKS)
def test_a_missing_compliance_framework_is_refused(framework):
    """All four are required: the evidence pack counts CONTROLS, so a gap silently
    shrinks a denominator -- the exact bug the pack was written to prevent."""
    comp = {"PCI-DSS": "1.1", "HIPAA": "164.312(a)", "SOC2": "CC6.1", "NIST": "AC-3"}
    del comp[framework]
    with pytest.raises(ValueError, match="compliance missing"):
        mk(compliance=comp)


def test_a_remediation_without_a_runnable_command_is_refused():
    """The house rule, enforced at declaration rather than by a later test -- and the
    rule SEGREC-01 tripped over."""
    with pytest.raises(ValueError, match="runnable aws CLI"):
        mk(remediation="Have a think about your security posture.")


def test_a_one_line_risk_is_refused():
    with pytest.raises(ValueError, match="risk is"):
        mk(risk="It is bad.")


def test_an_empty_impact_is_refused():
    with pytest.raises(ValueError, match="impact is empty"):
        mk(impact="")


def test_a_single_remediation_step_is_refused():
    """One step is almost always missing the verification that follows it."""
    with pytest.raises(ValueError, match="at least two"):
        mk(steps=("Turn it on.",))


def test_a_malformed_id_is_refused():
    with pytest.raises(ValueError, match="check id"):
        mk(cid="nonsense")


# ── the charter, enforced structurally ──────────────────────────────────────
def test_a_write_action_is_refused_as_a_charter_violation():
    """read-only-of-CONFIG is the charter. A declaration naming a write action is
    rejected here rather than caught in review."""
    with pytest.raises(ValueError, match="charter violation"):
        C.Perm("ec2:TerminateInstances", "stop an instance that looks suspicious to us")


@pytest.mark.parametrize("action", ["s3:PutBucketPolicy", "iam:CreateRole",
                                    "kms:Decrypt", "ec2:ModifySnapshotAttribute"])
def test_common_write_actions_are_all_refused(action):
    with pytest.raises(ValueError, match="not a read verb"):
        C.Perm(action, "a justification long enough to clear the minimum length check")


@pytest.mark.parametrize("action", ["ec2:DescribeInstances", "s3:GetBucketPolicy",
                                    "iam:ListRoles", "cloudtrail:LookupEvents",
                                    "dynamodb:BatchGetItem"])
def test_read_verbs_are_accepted(action):
    assert C.Perm(action, "a justification long enough to clear the minimum length").action


def test_an_unqualified_action_is_refused():
    with pytest.raises(ValueError, match="service-qualified"):
        C.Perm("DescribeInstances", "a justification long enough to clear the minimum")


def test_a_terse_justification_is_refused():
    """A reason nobody can read is a permission nobody can refuse on the merits."""
    with pytest.raises(ValueError, match="justification"):
        C.Perm("ec2:DescribeInstances", "read stuff")


# ── the collision guard ─────────────────────────────────────────────────────
def test_registering_the_same_id_twice_is_refused():
    C.register(mk("DUP-01"))
    with pytest.raises(ValueError, match="already registered"):
        C.register(mk("DUP-01"))


def test_a_merge_refuses_to_shadow_an_existing_map_entry():
    """The SEG-01 defect, structurally. dict.update bypasses the duplicate-key ratchet
    because that ratchet only sees dict LITERALS -- so the collision is refused here."""
    C.register(mk("SEG-01"))
    existing = {"SEG-01": "MEDIUM"}
    with pytest.raises(ValueError, match="already exist in CHECK_SEVERITY"):
        C.merge_maps(existing, {}, {})


def test_the_merge_error_names_the_colliding_ids():
    C.register(mk("BOOM-01"))
    with pytest.raises(ValueError, match=r"BOOM-01"):
        C.merge_detail({"BOOM-01": {}})


def test_a_clean_merge_populates_the_targets():
    C.register(mk("NEW-01"))
    sev, comp, rem = {"OLD-01": "LOW"}, {}, {}
    C.merge_maps(sev, comp, rem)
    assert sev == {"OLD-01": "LOW", "NEW-01": "HIGH"}
    assert "NEW-01" in comp and "NEW-01" in rem


def test_requirements_are_built_through_the_callers_factory():
    """The registry stays free of any import of the modules it feeds, so the caller
    supplies its own Requirement type."""
    C.register(mk("REQ-01"))
    made = []

    def factory(action, why):
        made.append((action, why))
        return (action, why)

    target = {}
    C.merge_requirements(target, factory)
    assert target["REQ-01"][0][0] == "ec2:DescribeInstances"
    assert len(made) == 1


def test_a_requirements_merge_also_refuses_a_collision():
    C.register(mk("REQ-02"))
    with pytest.raises(ValueError, match="REQUIREMENTS"):
        C.merge_requirements({"REQ-02": ()}, lambda a, w: (a, w))


# ── the registry is not a second source of truth for old checks ─────────────
def test_the_registry_starts_empty_of_the_legacy_literals():
    """This is an ADDITIVE path. Migrating 399 hand-authored entries to prove a point
    would be a large risky diff with no behavioural benefit."""
    from engine import aws_live_scanner as A
    legacy_only = set(A.CHECK_SEVERITY) - set(C.REGISTRY)
    assert len(legacy_only) > 300


def test_the_module_makes_no_aws_calls_and_imports_nothing_it_feeds():
    import inspect
    import re
    src = inspect.getsource(C)
    assert not re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests)\b", src, re.M)
    assert not re.findall(
        r"^\s*(?:import|from)\s+aws_(live_scanner|finding_detail|perm_ledger)\b",
        src, re.M)
