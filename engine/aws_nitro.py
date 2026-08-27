#!/usr/bin/env python3
"""aws_nitro.py — Phase 5 · slice 5.3: platform traffic-encryption evidence.

Most "is your traffic encrypted?" answers in a CNAPP are about TLS at an edge — a load
balancer listener, a certificate, a viewer protocol policy. Those matter and OverWatch
already checks them. This slice is about the layer *underneath*: whether the machines
themselves encrypt what they say to each other before any application gets a say.

AWS's Nitro System automatically encrypts in-transit traffic between instances — but only
for **supported instance types**, and the support is a property of the type rather than
something an operator configures. So the question "is east-west traffic encrypted at the
platform layer?" has a real, readable answer, and almost nothing asks it.

THE FIELD, VERBATIM
--------------------
``DescribeInstanceTypes`` → ``NetworkInfo.EncryptionInTransitSupported``:

    *"Indicates whether the instance type automatically encrypts in-transit traffic
    between instances."*

Read off the EC2 service model, API version **2016-11-15** — which is worth recording,
because the wheel ships nine EC2 API versions and the first one alphabetically is
``2014-09-01``, which predates ``DescribeInstanceTypes`` entirely. Taking the first match
returned an empty shape and briefly looked like the field did not exist.

WHAT THIS CAN AND CANNOT CLAIM
-------------------------------
It is a **capability** claim, not an observation. The field says the instance type
encrypts automatically; it does not say that any particular flow was encrypted, and
OverWatch has no way to watch a packet. The honest statement is therefore *"traffic
between these instances is encrypted by the platform"* for supported types, and *"the
platform does not encrypt it, so whatever the application does is the whole story"* for
unsupported ones — never *"your traffic is exposed"*, which would assert something no
configuration read establishes.

It also has a scope AWS defines and this module repeats rather than widens: the automatic
encryption covers traffic **between instances**, within a VPC or a peered VPC. It is not
a statement about traffic to S3, to the internet, or through a NAT gateway.

Pure functions over dicts. No boto3, no network, no I/O.
"""
from __future__ import annotations

from typing import Dict, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "NITRO", "XEN", "SUPPORTED", "UNSUPPORTED", "EC2_API_VERSION",
    "type_encryption", "instance_posture", "summarize_estate", "describe_gap",
    "SCOPE_NOTE",
]

#: Hypervisor values, from the InstanceTypeHypervisor enum.
NITRO = "nitro"
XEN = "xen"

#: NitroEnclavesSupport / NitroTpmSupport values.
SUPPORTED = "supported"
UNSUPPORTED = "unsupported"

#: Recorded because getting it wrong silently produced an empty answer: the botocore
#: wheel ships nine EC2 API versions and the oldest predates DescribeInstanceTypes.
EC2_API_VERSION = "2016-11-15"

SCOPE_NOTE = (
    "Nitro automatic encryption covers traffic BETWEEN INSTANCES within a VPC or a "
    "peered VPC. It is not a statement about traffic to S3, to the internet, or through "
    "a NAT gateway, and OverWatch does not extend it to those"
)


def _d(v) -> dict:
    return v if isinstance(v, dict) else {}


def type_encryption(info: Optional[dict]) -> dict:
    """What one instance TYPE guarantees about in-transit traffic.

    ``known`` is the field that matters most. ``EncryptionInTransitSupported`` is
    optional in the response, and an absent value means the answer was not returned —
    not that encryption is unsupported. Defaulting it to False would manufacture a
    finding out of a missing field, which is the phantom finding this codebase keeps
    catching."""
    d = _d(info)
    net = _d(d.get("NetworkInfo"))
    raw = net.get("EncryptionInTransitSupported")
    hyper = d.get("Hypervisor") or ""
    return {
        "instance_type": d.get("InstanceType") or "",
        "known": isinstance(raw, bool),
        "encrypts": raw is True,
        "hypervisor": hyper,
        "nitro": hyper == NITRO,
        "enclaves": d.get("NitroEnclavesSupport") == SUPPORTED,
        "tpm": d.get("NitroTpmSupport") == SUPPORTED,
    }


def instance_posture(instance: Optional[dict],
                     types: Optional[Mapping] = None) -> dict:
    """One running instance, joined to what its type guarantees.

    Only RUNNING instances are worth reporting: a stopped instance has no traffic to
    encrypt, and a finding about one is noise an operator cannot act on until they start
    it — at which point the next scan reports it."""
    i = _d(instance)
    itype = i.get("InstanceType") or ""
    enc = type_encryption(_d(types).get(itype)) if types else {
        "known": False, "encrypts": False, "instance_type": itype,
        "hypervisor": "", "nitro": False, "enclaves": False, "tpm": False}
    state = (_d(i.get("State")).get("Name") or "").lower()
    return {
        "instance_id": i.get("InstanceId") or "",
        "instance_type": itype,
        "state": state,
        "running": state == "running",
        **{k: v for k, v in enc.items() if k != "instance_type"},
    }


def summarize_estate(postures: Optional[Sequence[dict]]) -> dict:
    """The estate's platform-encryption position, counted rather than averaged.

    ``unknown`` is kept apart from ``unencrypted`` throughout. An instance whose type
    OverWatch could not describe is not an unencrypted one, and folding the two together
    is how a coverage gap becomes a finding."""
    running = [p for p in (postures or []) if isinstance(p, dict) and p.get("running")]
    enc = [p for p in running if p.get("known") and p.get("encrypts")]
    plain = [p for p in running if p.get("known") and not p.get("encrypts")]
    unknown = [p for p in running if not p.get("known")]
    xen = [p for p in running if p.get("hypervisor") == XEN]
    return {
        "running": len(running),
        "encrypted": len(enc),
        "unencrypted": len(plain),
        "unknown": len(unknown),
        "xen": len(xen),
        "unencrypted_types": sorted({p["instance_type"] for p in plain}),
        "xen_types": sorted({p["instance_type"] for p in xen}),
        "unknown_types": sorted({p["instance_type"] for p in unknown}),
        "all_encrypted": bool(running) and not plain and not unknown,
        "statement": _statement(len(running), len(enc), len(plain), len(unknown)),
    }


def _statement(running, enc, plain, unknown) -> str:
    if not running:
        return "no running instances to assess"
    bits = [f"{enc} of {running} running instance(s) are on types that automatically "
            f"encrypt in-transit traffic between instances"]
    if plain:
        bits.append(f"{plain} are not, so for those the platform contributes no "
                    f"encryption and whatever the application does is the whole story")
    if unknown:
        bits.append(f"{unknown} could not be resolved to an instance type and are "
                    f"reported as unknown rather than as unencrypted")
    return "; ".join(bits) + f". {SCOPE_NOTE}"


def describe_gap(posture: Optional[dict]) -> str:
    """One line for an instance the platform does not encrypt for."""
    p = _d(posture)
    if not p.get("running") or not p.get("known") or p.get("encrypts"):
        return ""
    hyper = f" on the {p['hypervisor']} hypervisor" if p.get("hypervisor") else ""
    return (f"Instance {p.get('instance_id')} runs on {p.get('instance_type')}{hyper}, "
            f"a type that does NOT automatically encrypt in-transit traffic between "
            f"instances — east-west traffic from it is encrypted only if the "
            f"application does it")
