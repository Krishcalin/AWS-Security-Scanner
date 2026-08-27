"""Phase 5 · slice 5.3 — platform traffic-encryption evidence.

Most "is your traffic encrypted?" answers in a CNAPP are about TLS at an edge. This is
the layer underneath: whether the machines encrypt what they say to each other before any
application gets a say. AWS's Nitro System does it automatically, but only for supported
instance types, and support is a property of the *type* rather than something an operator
configures — so the question has a readable answer and almost nothing asks it.

Three properties are defended here, and all three are about not over-claiming.

**It is a capability claim, not an observation.** The field says the type encrypts
automatically; it does not say any particular flow was encrypted, and OverWatch cannot
watch a packet.

**An absent field is unknown, not unsupported.** `EncryptionInTransitSupported` is
optional in the response. Defaulting it to False manufactures a finding out of a missing
field.

**The scope is AWS's, repeated rather than widened.** The automatic encryption covers
traffic between instances in a VPC or peered VPC — not to S3, not to the internet.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_nitro as N


def itype(name="m5.large", encrypts=True, hypervisor="nitro",
          enclaves=True, tpm=True, omit_field=False):
    net = {"NetworkPerformance": "Up to 10 Gigabit"}
    if not omit_field:
        net["EncryptionInTransitSupported"] = encrypts
    return {"InstanceType": name, "Hypervisor": hypervisor, "NetworkInfo": net,
            "NitroEnclavesSupport": "supported" if enclaves else "unsupported",
            "NitroTpmSupport": "supported" if tpm else "unsupported"}


def inst(iid="i-1", itype_name="m5.large", state="running"):
    return {"InstanceId": iid, "InstanceType": itype_name, "State": {"Name": state}}


# ── the type-level field ────────────────────────────────────────────────────
def test_a_supporting_type_reads_as_encrypting():
    t = N.type_encryption(itype(encrypts=True))
    assert t["known"] is True and t["encrypts"] is True


def test_a_non_supporting_type_reads_as_not_encrypting():
    t = N.type_encryption(itype(encrypts=False))
    assert t["known"] is True and t["encrypts"] is False


def test_an_absent_field_is_unknown_not_unsupported():
    """The load-bearing restraint. EncryptionInTransitSupported is optional, and
    defaulting it to False manufactures a finding out of a missing field."""
    t = N.type_encryption(itype(omit_field=True))
    assert t["known"] is False
    assert t["encrypts"] is False       # the value, but `known` is what callers gate on


def test_a_non_boolean_value_is_not_treated_as_true():
    d = itype()
    d["NetworkInfo"]["EncryptionInTransitSupported"] = "true"
    assert N.type_encryption(d)["known"] is False


def test_the_hypervisor_is_read():
    assert N.type_encryption(itype(hypervisor="nitro"))["nitro"] is True
    assert N.type_encryption(itype(hypervisor="xen"))["nitro"] is False


def test_enclave_and_tpm_support_are_read():
    t = N.type_encryption(itype(enclaves=True, tpm=False))
    assert t["enclaves"] is True and t["tpm"] is False


def test_the_api_version_is_recorded():
    """The wheel ships nine EC2 API versions and the oldest predates
    DescribeInstanceTypes entirely — taking the first match returned an empty shape and
    briefly looked like the field did not exist."""
    assert N.EC2_API_VERSION == "2016-11-15"


# ── joining an instance to its type ─────────────────────────────────────────
def test_a_running_instance_inherits_its_type_guarantee():
    types = {"m5.large": itype("m5.large", encrypts=True)}
    p = N.instance_posture(inst(), types)
    assert p["running"] is True and p["encrypts"] is True


def test_a_stopped_instance_is_marked_not_running():
    """A stopped instance has no traffic to encrypt, and a finding about one is noise
    until it starts — at which point the next scan reports it."""
    p = N.instance_posture(inst(state="stopped"), {"m5.large": itype()})
    assert p["running"] is False


def test_an_instance_whose_type_was_not_described_is_unknown():
    p = N.instance_posture(inst(itype_name="exotic.9xlarge"), {})
    assert p["known"] is False


# ── the estate summary ──────────────────────────────────────────────────────
def _estate():
    types = {"m5.large": itype("m5.large", encrypts=True),
             "t2.micro": itype("t2.micro", encrypts=False, hypervisor="xen"),
             "m4.large": itype("m4.large", omit_field=True)}
    rows = [inst("i-1", "m5.large"), inst("i-2", "t2.micro"),
            inst("i-3", "m4.large"), inst("i-4", "m5.large", state="stopped")]
    return [N.instance_posture(r, types) for r in rows]


def test_stopped_instances_are_excluded_from_the_count():
    s = N.summarize_estate(_estate())
    assert s["running"] == 3


def test_unknown_is_counted_apart_from_unencrypted():
    """An instance whose type could not be described is not an unencrypted one, and
    folding the two together turns a coverage gap into a finding."""
    s = N.summarize_estate(_estate())
    assert s["encrypted"] == 1 and s["unencrypted"] == 1 and s["unknown"] == 1


def test_the_statement_says_what_unknown_means():
    s = N.summarize_estate(_estate())
    assert "reported as unknown rather than as unencrypted" in s["statement"]


def test_the_statement_repeats_the_aws_scope_rather_than_widening_it():
    """The automatic encryption is between instances. Claiming it covers S3 or internet
    egress would be a stronger claim than the field supports."""
    s = N.summarize_estate(_estate())
    assert "BETWEEN INSTANCES" in s["statement"]
    assert "not a statement about traffic to S3" in s["statement"]


def test_an_all_encrypted_estate_is_recognised():
    types = {"m5.large": itype("m5.large", encrypts=True)}
    s = N.summarize_estate([N.instance_posture(inst(), types)])
    assert s["all_encrypted"] is True


def test_an_estate_with_an_unknown_is_not_all_encrypted():
    """Silence about one instance is not evidence about the estate."""
    s = N.summarize_estate(_estate())
    assert s["all_encrypted"] is False


def test_xen_instances_are_counted_separately():
    s = N.summarize_estate(_estate())
    assert s["xen"] == 1 and s["xen_types"] == ["t2.micro"]


def test_no_running_instances_says_so_rather_than_passing():
    s = N.summarize_estate([])
    assert s["running"] == 0
    assert "no running instances" in s["statement"]


# ── the per-instance line ───────────────────────────────────────────────────
def test_the_gap_line_names_the_type_and_what_remains():
    types = {"t2.micro": itype("t2.micro", encrypts=False, hypervisor="xen")}
    line = N.describe_gap(N.instance_posture(inst("i-2", "t2.micro"), types))
    assert "t2.micro" in line and "xen" in line
    assert "encrypted only if the application does it" in line


def test_no_gap_line_for_an_encrypting_instance():
    types = {"m5.large": itype(encrypts=True)}
    assert N.describe_gap(N.instance_posture(inst(), types)) == ""


def test_no_gap_line_for_an_unknown_instance():
    """Never assert a gap from a field that was not returned."""
    assert N.describe_gap(N.instance_posture(inst(), {})) == ""


# ── robustness ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", [None, {}, "nope", 7, {"NetworkInfo": "x"},
                                 {"State": "x"}])
def test_nothing_raises_on_malformed_input(bad):
    N.type_encryption(bad if isinstance(bad, dict) else None)
    N.instance_posture(bad if isinstance(bad, dict) else None, None)
    N.describe_gap(bad if isinstance(bad, dict) else None)
    N.summarize_estate(None)


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    assert not re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests)\b",
                          inspect.getsource(N), re.M)
