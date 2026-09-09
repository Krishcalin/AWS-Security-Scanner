#!/usr/bin/env python3
"""aws_cis_compute.py — the CIS AWS Compute Services Benchmark v2.0.0 controls that
OverWatch did not already hold.

WHY A SEPARATE BENCHMARK AT ALL. The 123 checks already carrying a ``CIS`` compliance
key are all CIS AWS **Foundations** numbering, and the Compute benchmark re-uses the same
section numbers for entirely different controls — Foundations 2.1.2 is about CloudTrail
log validation, Compute 2.1.2 is "AMIs are encrypted". Merging them into one ``CIS`` key
would silently mis-cite every mapping. Compute controls therefore carry their own
``CIS-COMPUTE`` key, a convention LMB-08/LMB-09 already established.

WHAT THIS MODULE IS FOR. Of the benchmark's 82 recommendations, 33 were already covered by
existing checks and 5 cannot be reached from the AWS control plane at all (four are Lightsail
in-guest state — applied updates, changed local passwords — and 16.1 says in its own audit
text that SimSpace Weaver exposes no encryption setting to inspect). The remaining 44 are
declared here, as 43 checks: LMB-13 answers both 12.4 and 12.9, because "least privilege"
and "no admin privileges" resolve to the same determinable fact about an execution role.

EVERY CHECK HERE ARRIVES WITH A DRIVING TEST. `docs/CHECK_FIRING.md` exists because this
codebase has repeatedly shipped checks that were registered, counted in the published
total, and unable to fire. Adding 43 at once is exactly the circumstance in which that
happens again, so `tests/test_cis_compute.py` drives each one to an actual FAIL and asserts
that severity, remediation and compliance render — the three things `_add` reads from the
catalogue for no status other than FAIL.

WHY SOME OF THESE ARE LOW. A benchmark recommendation is not automatically a security
defect. Untagged ECS clusters and un-propagated ASG tags are governance controls: real,
worth reporting, and not a HIGH. Declaring them LOW is what keeps a risk score meaning
something — see the CHECK_SEVERITY header note in aws_live_scanner.

ON THE SOURCE DOCUMENT. CIS benchmarks may not be redistributed, so the PDF is not in this
repository and no rationale, audit or remediation prose is copied from it. What is cited is
the recommendation NUMBER, which is a reference, and every description below is written
from the underlying AWS behaviour.

Pure. No boto3, no network, no I/O. The scanner passes in what it already fetched.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Mapping, Optional, Sequence

from engine import aws_checkdef as _cd
from engine.aws_checkdef import CheckDef as _C, Perm as _P

__all__ = [
    # EC2 / AMI / Auto Scaling
    "ami_naming", "ami_provenance", "org_tag_policy", "ec2_tag_policy",
    "instance_age", "instance_monitoring", "instance_default_sg", "eni_unused",
    "instance_stopped_age", "instance_delete_on_termination", "asg_tag_propagation",
    # ECS / Fargate
    "ecs_platform_version", "ecs_container_insights", "ecs_tags",
    "ecs_image_trust", "ecs_task_set_public_ip", "ecs_network_mode",
    "ecs_exec_logging", "ecs_fargate_ephemeral_cmk",
    # Lambda
    "lambda_insights", "lambda_role_sharing", "lambda_role_missing",
    "lambda_role_admin", "lambda_cross_account", "lambda_env_cmk",
    "lambda_layer_public", "lambda_recursion",
    # Lightsail
    "lightsail_ipv6", "lightsail_bucket_iam", "lightsail_bucket_attached",
    "lightsail_bucket_public", "lightsail_bucket_logging",
    # App Runner / Batch / Beanstalk / Image Builder
    "apprunner_egress", "batch_logging", "batch_confused_deputy",
    "beanstalk_managed_updates", "beanstalk_log_streaming",
    "beanstalk_access_logs", "beanstalk_https",
    "imagebuilder_distribution_public", "imagebuilder_cleanup_disabled",
    "CHECKS", "NOT_DETERMINABLE",
]

#: The five recommendations no agentless control-plane read can decide, and why. Kept as
#: data rather than prose so `docs/CIS_COMPUTE.md` and the coverage test read the same
#: list — a claim about what is out of scope is worth exactly as much as its reason.
NOT_DETERMINABLE: Dict[str, str] = {
    "5.1":  "whether the applications inside a Lightsail instance are patched is guest "
            "state; the Lightsail API exposes the blueprint, not what is installed",
    "5.2":  "application administrator credentials live inside the instance and are not "
            "readable through any AWS API",
    "5.11": "Windows patch level is guest state; Lightsail instances are not SSM-managed, "
            "so there is no patch-compliance surface to read either",
    "5.12": "the auto-generated password is retrievable only through "
            "GetInstanceAccessDetails, which returns a live credential -- reading one to "
            "audit it would breach the read-only-of-CONFIG charter",
    "16.1": "the benchmark's own audit text states that SimSpace Weaver exposes no "
            "encryption setting; the control is a property of the customer's application "
            "protocol, not of any AWS resource",
}


# ── shared helpers ───────────────────────────────────────────────────────────
def _as_dt(value) -> Optional[datetime]:
    """A boto3 timestamp, an ISO string, or nothing. Returns tz-aware UTC or None.

    Naive datetimes are treated as UTC rather than rejected: every AWS timestamp is UTC,
    and a test fixture that builds one with `datetime(2024, 1, 1)` is expressing the same
    instant an operator would read off the console."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            return _as_dt(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError:
            return None
    return None


def _age_days(value, now: Optional[datetime] = None) -> Optional[int]:
    dt = _as_dt(value)
    if dt is None:
        return None
    ref = _as_dt(now) or datetime.now(timezone.utc)
    return int((ref - dt).total_seconds() // 86400)


def _tags(obj, key: str = "Tags") -> Dict[str, str]:
    """AWS tags arrive as [{Key,Value}] almost everywhere and as {k: v} in ECS-adjacent
    APIs (which use lowercase `key`/`value`). Accept all three shapes."""
    raw = obj.get(key) if isinstance(obj, Mapping) else None
    if isinstance(raw, Mapping):
        return {str(k): str(v) for k, v in raw.items()}
    out: Dict[str, str] = {}
    for t in (raw or []):
        if not isinstance(t, Mapping):
            continue
        k = t.get("Key", t.get("key"))
        if k:
            out[str(k)] = str(t.get("Value", t.get("value", "")))
    return out


def _name_of(obj, fallback: str = "") -> str:
    return _tags(obj).get("Name") or fallback


# ══════════════════════════════════════════════════════════════════════════════
# Amazon Machine Images — CIS-Compute 2.1.1, 2.1.3
# ══════════════════════════════════════════════════════════════════════════════
def ami_naming(image: Mapping, pattern: Optional[str]) -> dict:
    """AMI-04 / 2.1.1 — an owned AMI whose name does not match the organisation's convention.

    EVALUATES ONLY WHEN A CONVENTION EXISTS. "Consistent naming" is a statement about an
    organisation's policy, and no property of an AMI reveals what that policy is. Guessing
    one would produce a check that fires on correct estates, so this returns
    ``evaluated=False`` until the operator supplies the pattern, and the scanner reports
    that as INFO rather than as a pass."""
    name = str(image.get("Name") or "").strip()
    image_id = str(image.get("ImageId") or "")
    if not pattern:
        return {"evaluated": False, "image_id": image_id, "name": name,
                "matches": None, "statement": ""}
    try:
        ok = bool(re.search(pattern, name))
    except re.error as e:
        return {"evaluated": False, "image_id": image_id, "name": name,
                "matches": None, "statement": f"invalid AMI naming pattern: {e}"}
    return {
        "evaluated": True, "image_id": image_id, "name": name, "matches": ok,
        "statement": (
            f"AMI {image_id} is named '{name or '(unnamed)'}', which does not match the "
            f"configured naming convention /{pattern}/. An image nobody can identify from "
            f"its name is an image nobody retires on schedule"
            if not ok else ""),
    }


def ami_provenance(instance: Mapping, image: Optional[Mapping],
                   own_account: str, trusted: Iterable[str] = ()) -> dict:
    """AMI-05 / 2.1.3 — a running instance booted from an AMI of unvetted origin.

    "Only approved AMIs" needs an approval list nobody has given us, but its determinable
    core does not: an AMI is either yours, or Amazon's, or a Marketplace product, or it
    belongs to a stranger. The last case is the one worth a finding, because an AMI is a
    whole disk — the account that published it chose every binary on it."""
    iid = str(instance.get("InstanceId") or "")
    ami = str(instance.get("ImageId") or "")
    known = {str(a) for a in trusted if a}
    if own_account:
        known.add(str(own_account))
    if image is None:
        # An AMI describe that returns nothing means the image was deregistered or belongs
        # to an account that will not show it to us. Either way the provenance is unknown,
        # which is a different claim from "untrusted" and must not be stated as one.
        return {"instance_id": iid, "image_id": ami, "owner": "", "known": False,
                "untrusted": False, "statement": ""}
    owner = str(image.get("OwnerId") or "")
    alias = str(image.get("ImageOwnerAlias") or "")
    public = bool(image.get("Public"))
    trusted_alias = alias in ("amazon", "aws-marketplace", "aws-backup-vault")
    untrusted = bool(owner) and owner not in known and not trusted_alias
    return {
        "instance_id": iid, "image_id": ami, "owner": owner, "alias": alias,
        "known": True, "untrusted": untrusted,
        "statement": (
            f"Instance {iid} runs AMI {ami}, owned by account {owner}"
            f"{' (public image)' if public else ''} — not this account, not an Amazon or "
            f"Marketplace alias, and not on the trusted-account list. An AMI is a full "
            f"disk image: its publisher chose every binary, service and credential baked "
            f"into the root volume"
            if untrusted else ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Organizations tag policy — CIS-Compute 2.3, 2.4
# ══════════════════════════════════════════════════════════════════════════════
def org_tag_policy(policies: Optional[Sequence[Mapping]],
                   org_available: bool = True) -> dict:
    """EC2-10 / 2.3 — no tag policy exists in the organisation.

    NAMED FOR WHAT IT RETURNS, not for what it asks. The obvious name was
    ``tag_policy_enabled``, and `test_decisions_d11_d13` rejected it: its mutation
    detector matches call names by verb prefix, and a pure predicate that reads like an
    `enable`/`tag` call is exactly the shape that tripwire exists to catch. Growing its
    allowlist to admit a false positive would blunt it; renaming costs nothing.

    ``policies=None`` means the ListPolicies call did not succeed; a standalone account
    (no organisation) is ``org_available=False``. Neither is a failure — an account that
    is not in an organisation cannot have an organisational tag policy, and reporting one
    as non-compliant would be a finding nobody can act on."""
    if not org_available:
        return {"applicable": False, "count": 0, "statement": ""}
    if policies is None:
        return {"applicable": False, "count": 0, "unknown": True, "statement": ""}
    n = len(policies)
    return {
        "applicable": True, "count": n, "unknown": False,
        "statement": (
            "The organisation has no tag policy. Tag policies are the only mechanism that "
            "makes tagging enforceable rather than aspirational, and every downstream "
            "control that selects resources by tag — cost allocation, backup selection, "
            "environment-scoped SCPs — silently under-selects when tags drift"
            if n == 0 else ""),
    }


def ec2_tag_policy(policy_docs: Optional[Sequence], org_available: bool = True) -> dict:
    """EC2-11 / 2.4 — tag policies exist but none of them governs EC2.

    A tag policy scopes itself with ``tags.<key>.enforced_for``, whose values are
    ``service:resourceType`` strings. A policy that governs only, say, ``s3:bucket``
    leaves every instance, volume and snapshot ungoverned."""
    if not org_available or policy_docs is None:
        return {"applicable": False, "covers_ec2": None, "statement": ""}
    covers = False
    for doc in policy_docs:
        for key_spec in ((doc or {}).get("tags") or {}).values():
            for target in ((key_spec or {}).get("enforced_for") or {}).get("@@assign", []):
                t = str(target)
                if t.startswith("ec2:") or t == "*":
                    covers = True
    return {
        "applicable": True, "covers_ec2": covers,
        "statement": (
            "Tag policies exist but none of them enforces tags for any ec2: resource "
            "type. EC2 is where untagged resources cost the most to untangle later: "
            "volumes and snapshots outlive the instance that created them, and without an "
            "owner tag there is nobody to ask whether they are still needed"
            if not covers else ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# EC2 instance hygiene — CIS-Compute 2.5, 2.6, 2.7, 2.10, 2.11, 2.12
# ══════════════════════════════════════════════════════════════════════════════
def instance_age(instance: Mapping, now=None, max_days: int = 180) -> dict:
    """EC2-12 / 2.5 — a running instance launched more than 180 days ago.

    The age is a proxy for a real property: an instance that has never been replaced has
    never been rebuilt from a current image, so its drift from the golden AMI is bounded
    only by how diligently it has been patched in place."""
    iid = str(instance.get("InstanceId") or "")
    days = _age_days(instance.get("LaunchTime"), now)
    old = days is not None and days > max_days
    return {
        "instance_id": iid, "days": days, "old": old,
        "statement": (
            f"Instance {iid} ({_name_of(instance, iid)}) has been running for {days} days, "
            f"past the {max_days}-day mark. A host that is never replaced accumulates every "
            f"change ever made to it by hand, and is rebuilt from a current image only if "
            f"somebody remembers to"
            if old else ""),
    }


def instance_monitoring(instance: Mapping) -> dict:
    """EC2-13 / 2.6 — detailed (1-minute) CloudWatch monitoring is off.

    Basic monitoring samples at 5 minutes. That is coarse enough that a burst of activity
    lasting four minutes — which is long enough to exfiltrate a great deal — can be
    averaged into a metric that never crosses an alarm threshold."""
    iid = str(instance.get("InstanceId") or "")
    state = str(((instance.get("Monitoring") or {}).get("State")) or "disabled")
    off = state not in ("enabled", "pending")
    return {
        "instance_id": iid, "state": state, "detailed": not off,
        "statement": (
            f"Instance {iid} ({_name_of(instance, iid)}) has detailed monitoring "
            f"{state} — metrics are published every 5 minutes rather than every minute. "
            f"Alarms built on 5-minute averages cannot see a short burst at all"
            if off else ""),
    }


def instance_default_sg(instance: Mapping, default_sg_ids: Iterable[str]) -> dict:
    """EC2-14 / 2.7 — the instance is attached to a VPC's default security group.

    VPC-04 already asks whether the default group has rules. This asks the other half, and
    it is the half that bites: the default group is shared by everything that forgot to
    choose one, so a rule added for a single host silently applies to all of them, and
    nothing in the group's name records who it was opened for."""
    iid = str(instance.get("InstanceId") or "")
    defaults = {str(g) for g in default_sg_ids if g}
    attached = {str(g.get("GroupId")) for g in (instance.get("SecurityGroups") or [])
                if g.get("GroupId")}
    hit = sorted(attached & defaults)
    return {
        "instance_id": iid, "groups": hit, "uses_default": bool(hit),
        "statement": (
            f"Instance {iid} ({_name_of(instance, iid)}) is attached to default security "
            f"group {', '.join(hit)}. The default group is whatever every unconfigured "
            f"resource lands in, so a rule opened for one workload is inherited by all of "
            f"them and its intent is recorded nowhere"
            if hit else ""),
    }


def eni_unused(eni: Mapping) -> dict:
    """EC2-15 / 2.10 — a network interface in the `available` state.

    A detached ENI still holds its private IP, its security groups and, if it had one, its
    Elastic IP association history. It is billed when it carries an EIP, and it keeps an
    address reserved inside a subnet that may be running short of them."""
    nid = str(eni.get("NetworkInterfaceId") or "")
    status = str(eni.get("Status") or "")
    return {
        "eni_id": nid, "status": status, "unused": status == "available",
        "statement": (
            f"Network interface {nid} is in the 'available' state — attached to nothing, "
            f"still holding private IP {eni.get('PrivateIpAddress') or '?'} and its "
            f"security groups, and still consuming an address in subnet "
            f"{eni.get('SubnetId') or '?'}"
            if status == "available" else ""),
    }


def instance_stopped_age(instance: Mapping, now=None, max_days: int = 90) -> dict:
    """EC2-16 / 2.11 — an instance that has been stopped for over 90 days.

    WHICH TIMESTAMP. The benchmark's audit reads LaunchTime, which for a stopped instance
    is when it last *started*, not when it stopped. StateTransitionReason carries the real
    stop time — 'User initiated (2024-01-15 10:00:00 GMT)' — so it is preferred, and
    LaunchTime is the fallback that keeps the check working when the reason string is
    absent or in a shape we do not recognise."""
    iid = str(instance.get("InstanceId") or "")
    state = str(((instance.get("State") or {}).get("Name")) or "")
    if state != "stopped":
        return {"instance_id": iid, "state": state, "days": None, "stale": False,
                "basis": "", "statement": ""}
    reason = str(instance.get("StateTransitionReason") or "")
    m = re.search(r"\((\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})", reason)
    if m:
        days, basis = _age_days(m.group(1).replace(" ", "T"), now), "stop time"
    else:
        days, basis = _age_days(instance.get("LaunchTime"), now), "last start"
    stale = days is not None and days > max_days
    return {
        "instance_id": iid, "state": state, "days": days, "stale": stale, "basis": basis,
        "statement": (
            f"Instance {iid} ({_name_of(instance, iid)}) has been stopped for {days} days "
            f"(by {basis}), past the {max_days}-day mark. A stopped instance still holds "
            f"its EBS volumes, its IAM instance profile and its place in the estate — it "
            f"costs storage, and it is not patched by anything, so it comes back worse "
            f"than it left"
            if stale else ""),
    }


def instance_delete_on_termination(instance: Mapping) -> dict:
    """EC2-17 / 2.12 — an attached EBS volume that outlives its instance.

    The orphan is the finding. A volume left behind when the instance is terminated keeps
    whatever was on it, is attached to nothing that would ever be patched or scanned, and
    is answerable to no owner — which is how a snapshot of production data ends up sitting
    in an account long after the workload that produced it was decommissioned."""
    iid = str(instance.get("InstanceId") or "")
    keep = []
    for bdm in (instance.get("BlockDeviceMappings") or []):
        ebs = bdm.get("Ebs") or {}
        if ebs.get("DeleteOnTermination") is False:
            keep.append(str(ebs.get("VolumeId") or bdm.get("DeviceName") or "?"))
    return {
        "instance_id": iid, "volumes": keep, "persists": bool(keep),
        "statement": (
            f"Instance {iid} ({_name_of(instance, iid)}) has {len(keep)} attached volume(s) "
            f"({', '.join(keep)}) set to survive termination. They will outlive the "
            f"instance holding whatever data was on them, attached to nothing, scanned by "
            f"nothing, and owned by nobody"
            if keep else ""),
    }


def asg_tag_propagation(asg: Mapping) -> dict:
    """ASG-02 / 2.14 — Auto Scaling group tags that are not propagated at launch.

    An ASG replaces instances continuously. If its tags do not propagate, every instance
    the group launches arrives untagged, which means it is invisible to every tag-scoped
    control in the account — backup selection, cost allocation, and any SCP or policy that
    keys off an environment tag."""
    name = str(asg.get("AutoScalingGroupName") or "")
    tags = list(asg.get("Tags") or [])
    unpropagated = sorted({str(t.get("Key")) for t in tags
                           if t.get("Key") and not t.get("PropagateAtLaunch", False)})
    return {
        "asg": name, "tag_count": len(tags), "untagged": not tags,
        "unpropagated": unpropagated, "bad": bool(unpropagated) or not tags,
        "statement": (
            (f"Auto Scaling group {name} carries no tags at all, so every instance it "
             f"launches arrives untagged"
             if not tags else
             f"Auto Scaling group {name} has tag(s) {', '.join(unpropagated)} with "
             f"PropagateAtLaunch=false, so instances it launches do not carry them") +
            ". Anything that selects resources by tag — backup plans, cost allocation, "
            "environment-scoped policy — silently skips every instance this group creates"
            if (unpropagated or not tags) else ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Amazon ECS — CIS-Compute 3.8 .. 3.16, and Fargate 11.1
# ══════════════════════════════════════════════════════════════════════════════
#: The oldest platform version that still receives Fargate security patches, per family.
#: Anything below these is pinned to a build AWS no longer updates.
_FARGATE_MIN = {"LINUX": (1, 4, 0), "WINDOWS": (1, 0, 0)}


def _version_tuple(v):
    try:
        return tuple(int(p) for p in str(v).split("."))
    except (TypeError, ValueError):
        return None


def ecs_platform_version(service: Mapping) -> dict:
    """ECS-09 / 3.8 — a Fargate service pinned below the supported platform version.

    ``LATEST`` is the passing value and a pinned version is the interesting one: pinning is
    how a service stops receiving the platform patches Fargate otherwise applies for you,
    and unlike an EC2 host there is no agent, no SSM inventory and no vulnerability scanner
    that would ever report the underlying runtime as behind."""
    name = str(service.get("serviceName") or "")
    caps = [str(c.get("capacityProvider") or "")
            for c in (service.get("capacityProviderStrategy") or [])]
    fargate = (str(service.get("launchType") or "") == "FARGATE"
               or any(c.startswith("FARGATE") for c in caps))
    if not fargate:
        return {"service": name, "applicable": False, "outdated": False, "statement": ""}
    version = str(service.get("platformVersion") or "LATEST")
    family = str(service.get("platformFamily") or "LINUX").upper()
    if version.upper() == "LATEST":
        return {"service": name, "applicable": True, "version": version,
                "family": family, "outdated": False, "statement": ""}
    got = _version_tuple(version)
    floor = _FARGATE_MIN.get(family, _FARGATE_MIN["LINUX"])
    outdated = got is None or got < floor
    return {
        "service": name, "applicable": True, "version": version, "family": family,
        "outdated": outdated,
        "statement": (
            f"ECS service {name} is pinned to Fargate platform version {version} "
            f"({family.title()}), below the {'.'.join(str(p) for p in floor)} floor. A "
            f"pinned platform version stops receiving the runtime patches AWS applies to "
            f"LATEST, and nothing runs inside a Fargate task that would ever report the gap"
            if outdated else ""),
    }


def ecs_container_insights(cluster: Mapping) -> dict:
    """ECS-10 / 3.9 — Container Insights is off on the cluster.

    Without it the cluster publishes cluster-level counters and nothing per task. That is
    the difference between knowing a task restarted forty times overnight and knowing only
    that the desired count was eventually met — which is exactly the signal that separates
    a crash-looping deployment from a container being killed by something."""
    name = str(cluster.get("clusterName") or "")
    settings = {str(s.get("name")): str(s.get("value"))
                for s in (cluster.get("settings") or []) if s.get("name")}
    value = settings.get("containerInsights", "disabled").lower()
    off = value not in ("enabled", "enhanced")
    return {
        "cluster": name, "value": value, "off": off,
        "statement": (
            f"ECS cluster {name} has Container Insights {value}. Per-task CPU, memory, "
            f"restart and network metrics are not collected, so a crash-looping or "
            f"resource-starved task is indistinguishable from a healthy one at the only "
            f"level the platform reports"
            if off else ""),
    }


def ecs_tags(resource: Mapping, kind: str, name: str) -> dict:
    """ECS-11/12/13 — 3.10 (services), 3.11 (clusters), 3.12 (task definitions).

    One evaluator for three recommendations because the fact is identical in all three:
    the resource carries no tags. It is a governance finding rather than a vulnerability,
    and it is declared LOW for that reason."""
    tags = _tags(resource, "tags") or _tags(resource, "Tags")
    return {
        "kind": kind, "name": name, "tags": tags, "untagged": not tags,
        "statement": (
            f"ECS {kind} {name} carries no tags. Nothing selects it by owner, environment "
            f"or cost centre, so it is absent from every tag-scoped policy, budget and "
            f"inventory report in the account — and there is nobody named to ask about it"
            if not tags else ""),
    }


def ecs_image_trust(image: str, own_account: str, trusted: Iterable[str] = ()) -> dict:
    """ECS-14 / 3.13 — a task definition pulling an image from outside the estate.

    "Trusted" is an organisational judgement, so what is decided here is the part that is
    not: whether the image comes from a registry this account controls. A Docker Hub or
    other public-registry reference is resolved at task start, by tag, from a namespace
    somebody else can push to."""
    ref = str(image or "")
    known = {str(a) for a in trusted if a}
    if own_account:
        known.add(str(own_account))
    m = re.match(r"^(\d{12})\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/", ref)
    account = m.group(1) if m else ""
    in_estate = bool(account) and account in known
    external = bool(ref) and not in_estate
    digest_pinned = "@sha256:" in ref
    return {
        "image": ref, "registry_account": account,
        "public_ecr": ref.startswith("public.ecr.aws/"),
        "in_estate": in_estate, "external": external, "digest_pinned": digest_pinned,
        "statement": (
            f"Task definition pulls '{ref}', which is not an ECR repository in this account"
            + (" and is not pinned to a digest" if not digest_pinned else "") +
            ". The reference is resolved at task start from a registry outside the estate, "
            "so what actually runs is whatever that registry serves at that moment"
            if external else ""),
    }


def ecs_task_set_public_ip(task_set: Mapping) -> dict:
    """ECS-15 / 3.14 — a task set that assigns public IPs.

    A task set is the unit an external deployment controller manages (CodeDeploy
    blue/green, or a controller of your own), and its network configuration is set
    independently of the service's. A service corrected to DISABLED can still launch
    public tasks through a task set nobody looked at."""
    tid = str(task_set.get("id") or task_set.get("taskSetArn") or "")
    cfg = ((task_set.get("networkConfiguration") or {}).get("awsvpcConfiguration") or {})
    value = str(cfg.get("assignPublicIp") or "DISABLED").upper()
    return {
        "task_set": tid, "assign_public_ip": value, "public": value == "ENABLED",
        "statement": (
            f"ECS task set {tid} has assignPublicIp=ENABLED. Its tasks get a routable "
            f"address on the task ENI itself, so every port the container listens on is "
            f"reachable from the internet subject only to the security group — and a task "
            f"set is configured separately from its service, so correcting the service "
            f"does not correct this"
            if value == "ENABLED" else ""),
    }


def ecs_network_mode(task_def: Mapping) -> dict:
    """ECS-16 / 3.15 — a task definition not using awsvpc network mode.

    ECS-06 covers ``host``, which is an escape primitive. This covers the rest: ``bridge``
    and ``none`` are not dangerous in themselves, but under bridge every task on an
    instance shares that instance's ENI and therefore its security groups, so per-task
    network isolation does not exist and a rule written for one task applies to all."""
    fam = str(task_def.get("family") or "")
    mode = str(task_def.get("networkMode") or "bridge")
    bad = mode not in ("awsvpc", "host")
    return {
        "family": fam, "mode": mode, "not_awsvpc": bad,
        "statement": (
            f"Task definition {fam} uses networkMode={mode} rather than awsvpc. Every task "
            f"on the host shares the instance ENI and its security groups, so tasks cannot "
            f"be isolated from one another or granted different network access, and a "
            f"security-group rule written for one is inherited by all of them"
            if bad else ""),
    }


def ecs_exec_logging(cluster: Mapping, exec_enabled_services: Sequence[str]) -> dict:
    """ECS-17 / 3.16 — ECS Exec is in use on a cluster that does not log the sessions.

    ECS Exec is an interactive shell into a running container. Only clusters that actually
    have an Exec-enabled service are evaluated: where nobody can start a session there is
    nothing to log, and a finding on a cluster with no exposure is how a check teaches
    people to ignore it."""
    name = str(cluster.get("clusterName") or "")
    services = [str(s) for s in (exec_enabled_services or [])]
    if not services:
        return {"cluster": name, "applicable": False, "logging": "", "unlogged": False,
                "services": [], "statement": ""}
    cfg = ((cluster.get("configuration") or {}).get("executeCommandConfiguration") or {})
    logging = str(cfg.get("logging") or "DEFAULT").upper()
    unlogged = logging != "OVERRIDE"
    return {
        "cluster": name, "applicable": True, "logging": logging, "unlogged": unlogged,
        "services": services,
        "statement": (
            f"ECS cluster {name} has {len(services)} service(s) with ECS Exec enabled "
            f"({', '.join(services[:4])}) and session logging set to {logging}. Anyone who "
            f"can call ExecuteCommand gets an interactive shell inside a running container, "
            f"and no record of what was typed reaches CloudWatch Logs or S3"
            if unlogged else ""),
    }


def ecs_fargate_ephemeral_cmk(cluster: Mapping) -> dict:
    """FARGATE-03 / 11.1 — Fargate ephemeral storage encrypted with an AWS-owned key.

    Fargate task storage is always encrypted; the control is about WHICH key. An AWS-owned
    key has no key policy to review, no grant to revoke and produces no CloudTrail entry
    naming your account — so there is no way to evidence who decrypted a task's scratch
    volume, and no way to make it undecryptable in a hurry."""
    name = str(cluster.get("clusterName") or "")
    cfg = ((cluster.get("configuration") or {}).get("managedStorageConfiguration") or {})
    key = str(cfg.get("fargateEphemeralStorageKmsKeyId") or "")
    return {
        "cluster": name, "kms_key": key, "aws_owned": not key,
        "statement": (
            f"ECS cluster {name} encrypts Fargate ephemeral storage with an AWS-owned key. "
            f"There is no key policy to review, no grant to revoke and no CloudTrail entry "
            f"naming this account when it is used, so neither access to task scratch space "
            f"nor its destruction can be evidenced or controlled"
            if not key else ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# AWS Lambda — CIS-Compute 12.2, 12.5, 12.7, 12.9, 12.10, 12.12, 12.13, 12.14
# ══════════════════════════════════════════════════════════════════════════════
_INSIGHTS_LAYER = re.compile(r":layer:LambdaInsightsExtension", re.I)


def lambda_insights(function: Mapping) -> dict:
    """LMB-10 / 12.2 — the CloudWatch Lambda Insights extension is not attached.

    Lambda publishes duration, errors and throttles by default and nothing about what the
    function was doing. Insights adds the per-invocation CPU, memory, network and
    init-duration series, which is the only in-band way to notice that a function's
    resource profile changed without its code changing."""
    name = str(function.get("FunctionName") or "")
    layers = [str(l.get("Arn") or "") for l in (function.get("Layers") or [])]
    on = any(_INSIGHTS_LAYER.search(a) for a in layers)
    return {
        "function": name, "layers": layers, "enabled": on,
        "statement": (
            f"Lambda function {name} has no CloudWatch Lambda Insights extension layer. "
            f"Only duration, error and throttle counts are published, so a change in the "
            f"function's memory, CPU or network profile — the signature of a swapped "
            f"dependency or an injected payload — produces no observable signal at all"
            if not on else ""),
    }


def lambda_role_sharing(functions: Sequence[Mapping]) -> List[dict]:
    """LMB-11 / 12.5 — several functions sharing one execution role.

    A shared execution role is the union of everything any of its functions needs, so each
    one runs with the permissions of all the others. It also destroys attribution: a
    CloudTrail entry naming the role cannot say which function made the call."""
    by_role: Dict[str, List[str]] = {}
    for f in functions or []:
        role = str(f.get("Role") or "")
        if role:
            by_role.setdefault(role, []).append(str(f.get("FunctionName") or ""))
    out: List[dict] = []
    for role, names in sorted(by_role.items()):
        if len(names) < 2:
            continue
        names = sorted(names)
        out.append({
            "role": role, "functions": names, "count": len(names),
            "statement": (
                f"Execution role {role.rsplit('/', 1)[-1]} is shared by {len(names)} "
                f"functions ({', '.join(names[:4])}). Each of them runs with the union of "
                f"what all of them need, and a CloudTrail entry naming the role cannot say "
                f"which function made the call"),
        })
    return out


def lambda_role_missing(function: Mapping, role_exists: Optional[bool]) -> dict:
    """LMB-12 / 12.7 — the function references an execution role that no longer exists.

    ``role_exists=None`` means iam:GetRole did not answer, which is not the same as the
    role being gone and must not be reported as it. When the role really is deleted the
    function does not fail loudly — it fails at invocation, so the breakage surfaces on
    whatever the next trigger happens to be, at whatever hour that is."""
    name = str(function.get("FunctionName") or "")
    role = str(function.get("Role") or "")
    return {
        "function": name, "role": role, "known": role_exists is not None,
        "missing": role_exists is False,
        "statement": (
            f"Lambda function {name} references execution role {role.rsplit('/', 1)[-1]}, "
            f"which does not exist. Every invocation fails at assume-role time, and it "
            f"fails when the trigger fires rather than when the role was deleted — so the "
            f"outage arrives detached in time from the change that caused it"
            if role_exists is False else ""),
    }


def lambda_role_admin(function: Mapping, statements: Sequence[Mapping]) -> dict:
    """LMB-13 / 12.9, and the determinable core of 12.4 — an admin execution role.

    A function's execution role is assumed by the Lambda service on the function's behalf,
    which means the role's permissions are exactly what an attacker gets from any code
    execution inside the handler — a deserialisation flaw, a vulnerable dependency, or an
    injected field in an event the function parses."""
    name = str(function.get("FunctionName") or "")
    role = str(function.get("Role") or "")
    admin: List[str] = []
    for st in statements or []:
        if str(st.get("Effect", "Allow")) != "Allow":
            continue
        actions = st.get("Action") or []
        if isinstance(actions, str):
            actions = [actions]
        resources = st.get("Resource") or []
        if isinstance(resources, str):
            resources = [resources]
        if "*" in [str(a) for a in actions] and \
                (not resources or "*" in [str(r) for r in resources]):
            admin.append(str(st.get("Sid") or "(unnamed statement)"))
    return {
        "function": name, "role": role, "statements": admin, "admin": bool(admin),
        "statement": (
            f"Lambda function {name} runs with execution role {role.rsplit('/', 1)[-1]}, "
            f"which allows Action '*' on Resource '*' ({', '.join(admin)}). Any code "
            f"execution inside the handler — a vulnerable dependency, a deserialisation "
            f"bug, an injected event field — inherits full administrative access to the "
            f"account"
            if admin else ""),
    }


def lambda_cross_account(function_name: str, statements: Sequence[Mapping],
                         own_account: str, trusted: Iterable[str] = ()) -> dict:
    """LMB-14 / 12.10 — the resource policy grants invoke to an unrecognised account.

    LMB-01 covers a wildcard principal. This covers the quieter case: a named account that
    is not yours and not on the allowlist. That is how a grant added for a partner
    integration outlives the integration — nothing expires it and nothing reports it."""
    known = {str(a) for a in trusted if a}
    if own_account:
        known.add(str(own_account))
    foreign = set()
    for st in statements or []:
        if str(st.get("Effect", "Allow")) != "Allow":
            continue
        prin = st.get("Principal") or {}
        vals: List[str] = []
        if isinstance(prin, str):
            vals = [prin]
        elif isinstance(prin, Mapping):
            aws = prin.get("AWS")
            vals = [aws] if isinstance(aws, str) else [str(a) for a in (aws or [])]
        for v in vals:
            v = str(v)
            if v == "*":
                continue                      # LMB-01's finding, not this one
            m = re.search(r"(\d{12})", v)
            if m and m.group(1) not in known:
                foreign.add(m.group(1))
    return {
        "function": str(function_name or ""), "accounts": sorted(foreign),
        "cross_account": bool(foreign),
        "statement": (
            f"Lambda function {function_name} grants invoke permission to account(s) "
            f"{', '.join(sorted(foreign))}, which are neither this account nor on the "
            f"trusted-account list. A resource-policy grant has no expiry and appears in "
            f"no IAM report, so it outlives whatever integration it was added for"
            if foreign else ""),
    }


def lambda_env_cmk(function: Mapping) -> dict:
    """LMB-15 / 12.12 — environment variables encrypted with the AWS-managed Lambda key.

    Values are always encrypted at rest. The control is whose key: with the default key
    every principal holding lambda:GetFunctionConfiguration reads the plaintext, because
    decryption is transparent to the caller. A CMK moves that decision into a key policy
    somebody can write, review and revoke."""
    name = str(function.get("FunctionName") or "")
    env = (function.get("Environment") or {}).get("Variables") or {}
    key = str(function.get("KMSKeyArn") or "")
    return {
        "function": name, "var_count": len(env), "kms_key": key,
        "default_key": bool(env) and not key,
        "statement": (
            f"Lambda function {name} has {len(env)} environment variable(s) encrypted with "
            f"the AWS-managed Lambda key rather than a customer-managed key. Anyone "
            f"holding lambda:GetFunctionConfiguration reads the plaintext values, because "
            f"that key has no policy you can narrow and decryption is transparent"
            if (env and not key) else ""),
    }


def lambda_layer_public(layer_name: str, version, statements: Sequence[Mapping]) -> dict:
    """LMB-16 / 12.13 — a layer version shared with every AWS account.

    A layer is code prepended to a function's runtime. Publishing one publicly exposes
    whatever was packaged into it — and layers are exactly where build-time material ends
    up, because they are the part of a deployment nobody re-reviews."""
    public = False
    for st in statements or []:
        if str(st.get("Effect", "Allow")) != "Allow":
            continue
        prin = st.get("Principal")
        if prin == "*" or (isinstance(prin, Mapping) and prin.get("AWS") == "*"):
            public = True
    return {
        "layer": str(layer_name or ""), "version": version, "public": public,
        "statement": (
            f"Lambda layer {layer_name} version {version} has a permission policy granting "
            f"a wildcard principal. Every AWS account can download the layer, and a layer "
            f"is a packaged filesystem — whatever was in the build directory when it was "
            f"published went out with it"
            if public else ""),
    }


def lambda_recursion(function_name: str, recursive_loop: Optional[str]) -> dict:
    """LMB-17 / 12.14 — recursive-loop detection turned off.

    The account default is Terminate; ``Allow`` is a deliberate opt-out. With detection off
    a function that triggers its own source — the classic Lambda writes to the bucket that
    triggers Lambda — runs until the concurrency limit or the bill stops it, and it
    consumes the account's shared concurrency pool the whole time."""
    value = str(recursive_loop or "").strip()
    return {
        "function": str(function_name or ""), "value": value, "allowed": value == "Allow",
        "statement": (
            f"Lambda function {function_name} has recursive-loop detection set to Allow. "
            f"The safety net that halts a function which re-triggers itself is switched "
            f"off, so a self-triggering loop runs until it exhausts the account's shared "
            f"concurrency pool — taking every other function in the account with it"
            if value == "Allow" else ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Amazon Lightsail — CIS-Compute 5.6 .. 5.10
# ══════════════════════════════════════════════════════════════════════════════
def lightsail_ipv6(instance: Mapping) -> dict:
    """LSAIL-03 / 5.6 — IPv6 networking is enabled on a Lightsail instance.

    Lightsail's instance firewall is written per address family, and the IPv6 rules are a
    separate list on the same port entries. An operator who closes a port for IPv4 and
    never scrolls to the IPv6 column leaves it open on an address that is routable from
    the whole internet and appears in no IPv4 scan."""
    name = str(instance.get("name") or "")
    addrs = [str(a) for a in (instance.get("ipv6Addresses") or []) if a]
    enabled = bool(addrs) or bool(instance.get("isStaticIp") and instance.get("ipv6Address"))
    return {
        "instance": name, "addresses": addrs, "enabled": enabled,
        "statement": (
            f"Lightsail instance {name} has IPv6 networking enabled "
            f"({', '.join(addrs) or 'address not reported'}). Lightsail keeps a separate "
            f"IPv6 rule list on every firewall port entry, so a port closed for IPv4 can "
            f"remain open on an address that no IPv4 scan of this estate will ever show"
            if enabled else ""),
    }


def lightsail_bucket_public(bucket: Mapping) -> dict:
    """LSAIL-06 / 5.9 — a Lightsail bucket readable by anyone.

    Two independent settings make a bucket public: ``getObject: public`` makes every
    object readable, and ``allowPublicOverrides: true`` lets an individual object be made
    public later without the bucket-level setting ever changing."""
    name = str(bucket.get("name") or "")
    rules = bucket.get("accessRules") or {}
    get_object = str(rules.get("getObject") or "private")
    overrides = bool(rules.get("allowPublicOverrides"))
    public = get_object == "public" or overrides
    why = []
    if get_object == "public":
        why.append("every object is readable anonymously (getObject=public)")
    if overrides:
        why.append("individual objects may be made public "
                   "(allowPublicOverrides=true) without changing this setting")
    return {
        "bucket": name, "get_object": get_object, "allow_overrides": overrides,
        "public": public,
        "statement": (
            f"Lightsail bucket {name} is publicly accessible: {'; '.join(why)}. Lightsail "
            f"buckets sit outside the S3 console and outside S3 Block Public Access, so "
            f"neither the account-level guardrail nor an S3 audit covers them"
            if public else ""),
    }


def lightsail_bucket_logging(bucket: Mapping) -> dict:
    """LSAIL-07 / 5.10 — access logging is off on a Lightsail bucket.

    Without it there is no record of who read what. For a bucket that is or ever becomes
    public that is the difference between knowing an exposure was exploited and being
    unable to say either way, which is the position that turns a misconfiguration into a
    disclosure that must be assumed."""
    name = str(bucket.get("name") or "")
    cfg = bucket.get("accessLogConfig") or {}
    on = bool(cfg.get("enabled"))
    return {
        "bucket": name, "enabled": on,
        "statement": (
            f"Lightsail bucket {name} has access logging disabled. No record is kept of "
            f"which objects were read or by whom, so if the bucket is ever found exposed "
            f"there is no way to establish whether anything was taken"
            if not on else ""),
    }


def lightsail_bucket_iam(bucket: Mapping) -> dict:
    """LSAIL-04 / 5.7 — bucket access granted through access keys rather than IAM.

    A Lightsail bucket can be reached two ways: an IAM principal granted s3 actions on its
    ARN, or a bucket access key. The key is a long-lived static credential with no policy,
    no condition keys and no CloudTrail principal beyond the key id — so every access looks
    the same regardless of who made it."""
    name = str(bucket.get("name") or "")
    keys = list(bucket.get("accessKeys") or [])
    readonly = list(bucket.get("readonlyAccessAccounts") or [])
    return {
        "bucket": name, "access_keys": len(keys), "readonly_accounts": readonly,
        "key_based": bool(keys),
        "statement": (
            f"Lightsail bucket {name} has {len(keys)} bucket access key(s). A bucket access "
            f"key is a static credential with no attached policy, no condition keys and no "
            f"expiry — it cannot be scoped to a prefix or an IP, and CloudTrail records the "
            f"key id rather than a principal anyone can look up"
            if keys else ""),
    }


def lightsail_bucket_attached(bucket: Mapping) -> dict:
    """LSAIL-05 / 5.8 — no Lightsail resource is attached to the bucket.

    Attaching an instance is what lets it reach the bucket through its instance role
    instead of an embedded key. A bucket with no attached resource is being reached some
    other way — which in Lightsail means a key sitting in a config file on the instance."""
    name = str(bucket.get("name") or "")
    # GetBuckets returns [{name, resourceType}]; older shapes and fixtures use bare
    # strings. Accept both rather than silently reading an empty list from the wrong one.
    attached = []
    for r in (bucket.get("resourcesReceivingAccess") or []):
        label = str((r or {}).get("name") or "") if isinstance(r, Mapping) else str(r or "")
        if label:
            attached.append(label)
    return {
        "bucket": name, "attached": attached, "unattached": not attached,
        "statement": (
            f"Lightsail bucket {name} has no attached Lightsail resource. Attachment is "
            f"what lets an instance read the bucket through its own identity, so a bucket "
            f"in use with none is being reached by a static access key stored on the "
            f"instance instead"
            if not attached else ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# AWS App Runner — CIS-Compute 6.1
# ══════════════════════════════════════════════════════════════════════════════
def apprunner_egress(service: Mapping) -> dict:
    """APRUN-01 / 6.1 — an App Runner service whose outbound traffic leaves via the internet.

    With the default egress the service reaches its source repository, its database and
    everything else over the public internet from an AWS-owned address you do not control.
    A VPC connector puts that traffic in your VPC, where a security group, a route table
    and flow logs all apply to it."""
    name = str(service.get("ServiceName") or "")
    egress = ((service.get("NetworkConfiguration") or {}).get("EgressConfiguration") or {})
    etype = str(egress.get("EgressType") or "DEFAULT").upper()
    ingress = ((service.get("NetworkConfiguration") or {}).get("IngressConfiguration") or {})
    public_ingress = ingress.get("IsPubliclyAccessible")
    return {
        "service": name, "egress_type": etype, "public_egress": etype != "VPC",
        "public_ingress": bool(public_ingress),
        "statement": (
            f"App Runner service {name} uses EgressType={etype}. All outbound traffic — "
            f"source-repository pulls, database connections, third-party calls — leaves "
            f"over the public internet from an AWS-managed address, so no security group, "
            f"route table or VPC flow log in your account applies to any of it"
            if etype != "VPC" else ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# AWS Batch — CIS-Compute 8.1, 8.2
# ══════════════════════════════════════════════════════════════════════════════
def batch_logging(job_definition: Mapping) -> dict:
    """BATCH-01 / 8.1 — a job definition with no log configuration.

    A Batch job is a container that runs once and disappears. If its log driver is not
    configured the stdout and stderr of that run are gone the moment the container exits,
    which means a job that failed, or was made to do something else, leaves nothing behind
    to look at."""
    name = str(job_definition.get("jobDefinitionName") or "")
    props = job_definition.get("containerProperties") or {}
    node = job_definition.get("nodeProperties") or {}
    containers = [props] if props else [
        (n or {}).get("container") or {} for n in (node.get("nodeRangeProperties") or [])]
    missing = [i for i, c in enumerate(containers) if not (c or {}).get("logConfiguration")]
    return {
        "job_definition": name, "containers": len(containers), "missing": missing,
        "unlogged": bool(missing) and bool(containers),
        "statement": (
            f"Batch job definition {name} has {len(missing)} of {len(containers)} container "
            f"definition(s) with no logConfiguration. A Batch job runs once and exits, so "
            f"anything it wrote to stdout or stderr is destroyed with the container and "
            f"there is nothing to review afterwards"
            if (missing and containers) else ""),
    }


def batch_confused_deputy(role_name: str, trust_doc: Optional[Mapping]) -> dict:
    """BATCH-02 / 8.2 — a Batch service role with no confused-deputy condition.

    The role trusts ``batch.amazonaws.com``, and that service acts for every Batch caller,
    not only yours. Without an ``aws:SourceArn`` or ``aws:SourceAccount`` condition the
    trust says "any Batch request may assume me", which is the confused-deputy shape AWS
    documents for every service-linked trust."""
    stmts = (trust_doc or {}).get("Statement") or []
    if isinstance(stmts, Mapping):
        stmts = [stmts]
    batch_stmts, guarded, wildcarded = [], False, False
    for st in stmts:
        prin = (st or {}).get("Principal") or {}
        svc = prin.get("Service") if isinstance(prin, Mapping) else None
        svcs = [svc] if isinstance(svc, str) else [str(s) for s in (svc or [])]
        if not any("batch" in str(s) for s in svcs):
            continue
        batch_stmts.append(st)
        cond = (st.get("Condition") or {})
        for op, kv in cond.items():
            for key, val in (kv or {}).items():
                if str(key).lower() not in ("aws:sourcearn", "aws:sourceaccount"):
                    continue
                vals = [val] if isinstance(val, str) else [str(v) for v in (val or [])]
                # A SourceArn ending in /* names a resource TYPE, not a resource: it
                # re-admits every compute environment in the account, which is the whole
                # population the condition was supposed to narrow.
                if all(str(v).rstrip().endswith("*") for v in vals) and vals:
                    wildcarded = True
                else:
                    guarded = True
    applicable = bool(batch_stmts)
    return {
        "role": str(role_name or ""), "applicable": applicable, "guarded": guarded,
        "wildcarded": wildcarded, "unguarded": applicable and not guarded,
        "statement": (
            f"IAM role {role_name} is assumable by batch.amazonaws.com "
            + ("with an aws:SourceArn condition that ends in a wildcard, which re-admits "
               "every Batch resource in the account"
               if wildcarded else "with no aws:SourceArn or aws:SourceAccount condition") +
            ". The Batch service assumes this role on behalf of whoever asks it to, so the "
            "trust as written says any Batch request may use it"
            if (applicable and not guarded) else ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# AWS Elastic Beanstalk — CIS-Compute 10.1 .. 10.4
# ══════════════════════════════════════════════════════════════════════════════
def _option(settings: Sequence[Mapping], namespace: str, name: str) -> Optional[str]:
    """One Beanstalk configuration option value, or None if it is not set.

    Beanstalk returns configuration as a flat list of (Namespace, OptionName, Value)
    triples, and an option that has never been set is ABSENT rather than defaulted — so
    None and "false" have to stay distinguishable."""
    for s in settings or []:
        if str((s or {}).get("Namespace")) == namespace and \
                str((s or {}).get("OptionName")) == name:
            v = s.get("Value")
            return None if v is None else str(v)
    return None


def beanstalk_managed_updates(env_name: str, settings: Sequence[Mapping]) -> dict:
    """EB-01 / 10.1 — managed platform updates are not enabled.

    Beanstalk owns the platform beneath the application — the AMI, the language runtime,
    the proxy. With managed updates off, nothing patches any of it: the platform version
    stays wherever it was on the day the environment was created, and no vulnerability
    scanner in the account reports on a Beanstalk platform version."""
    enabled = _option(settings, "aws:elasticbeanstalk:managedactions", "ManagedActionsEnabled")
    level = _option(settings, "aws:elasticbeanstalk:managedactions:platformupdate",
                    "UpdateLevel")
    off = str(enabled).lower() != "true"
    return {
        "environment": str(env_name or ""), "enabled": enabled, "update_level": level,
        "off": off,
        "statement": (
            f"Beanstalk environment {env_name} has managed platform updates disabled "
            f"(ManagedActionsEnabled={enabled!r}). The platform version — the AMI, the "
            f"language runtime and the proxy Beanstalk manages for you — stays where it "
            f"was on the day the environment was created, and no scanner in the account "
            f"reports on a Beanstalk platform version"
            if off else ""),
    }


def beanstalk_log_streaming(env_name: str, settings: Sequence[Mapping]) -> dict:
    """EB-02 / 10.2 — instance logs are not persisted off the instance.

    Beanstalk instances are replaced by deployments, scaling and health checks. Logs that
    live only on the instance are destroyed with it, so the logs describing why an instance
    was unhealthy are deleted by the act of replacing it."""
    stream = _option(settings, "aws:elasticbeanstalk:cloudwatch:logs", "StreamLogs")
    retention = _option(settings, "aws:elasticbeanstalk:cloudwatch:logs", "RetentionInDays")
    off = str(stream).lower() != "true"
    return {
        "environment": str(env_name or ""), "stream_logs": stream,
        "retention": retention, "off": off,
        "statement": (
            f"Beanstalk environment {env_name} does not stream instance logs off the host "
            f"(StreamLogs={stream!r}). Instances are replaced by every deployment, scaling "
            f"event and failed health check, and the logs explaining why go with them"
            if off else ""),
    }


def beanstalk_access_logs(env_name: str, settings: Sequence[Mapping]) -> dict:
    """EB-03 / 10.3 — the environment's load balancer does not write access logs.

    The access log is the only per-request record of what reached the application. Without
    it the environment can say how many requests failed and nothing about which paths,
    which clients or which payloads — the exact detail an investigation needs and cannot
    reconstruct after the fact."""
    v2 = _option(settings, "aws:elbv2:loadbalancer", "AccessLogsS3Enabled")
    v1 = _option(settings, "aws:elb:loadbalancer", "AccessLogsS3Enabled")
    value = v2 if v2 is not None else v1
    off = str(value).lower() != "true"
    return {
        "environment": str(env_name or ""), "enabled": value, "off": off,
        "statement": (
            f"Beanstalk environment {env_name} has load-balancer access logs disabled "
            f"(AccessLogsS3Enabled={value!r}). Nothing records which paths were requested, "
            f"by which clients, with what result — so an investigation has request counts "
            f"and no requests"
            if off else ""),
    }


def beanstalk_https(env_name: str, settings: Sequence[Mapping]) -> dict:
    """EB-04 / 10.4 — no HTTPS listener on the environment's load balancer.

    A Beanstalk environment terminates TLS at its load balancer or not at all. With only an
    HTTP listener, credentials and session cookies cross the internet in clear text, and
    nothing inside the environment can tell that they did."""
    # Listener options are namespaced per port: aws:elbv2:listener:443 / aws:elb:listener:80.
    # `Protocol` (v2) and `ListenerProtocol` (classic) name the same thing.
    protocols: Dict[str, str] = {}
    for s in settings or []:
        ns = str((s or {}).get("Namespace") or "")
        if not (ns.startswith("aws:elbv2:listener:") or ns.startswith("aws:elb:listener:")):
            continue
        if str((s or {}).get("OptionName")) in ("Protocol", "ListenerProtocol"):
            protocols[ns.rsplit(":", 1)[-1]] = str(s.get("Value") or "")
    secure = {p for p, proto in protocols.items() if proto.upper() in ("HTTPS", "SSL", "TLS")}
    insecure = {p for p, proto in protocols.items() if proto.upper() in ("HTTP", "TCP")}
    return {
        "environment": str(env_name or ""), "protocols": protocols,
        "secure_ports": sorted(secure), "insecure_ports": sorted(insecure),
        "no_https": bool(protocols) and not secure,
        "statement": (
            f"Beanstalk environment {env_name} has no HTTPS listener — its load balancer "
            f"listens only on {', '.join(sorted(insecure)) or 'plaintext protocols'}. "
            f"Credentials, session cookies and everything else cross the public internet in "
            f"clear text, and nothing inside the environment can tell that they did"
            if (protocols and not secure) else ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# EC2 Image Builder — CIS-Compute 17.1, 17.2
# ══════════════════════════════════════════════════════════════════════════════
def imagebuilder_distribution_public(dist_config: Mapping) -> dict:
    """IMGB-02 / 17.1 — a distribution configuration that publishes AMIs publicly.

    IMGB-01 reads the Image Builder *resource* policy, which governs who may use the
    pipeline. This reads the distribution settings, which govern what happens to every AMI
    the pipeline produces — so a single ``userGroups: [all]`` publishes every future build,
    including ones whose contents nobody has reviewed yet."""
    name = str(dist_config.get("name") or dist_config.get("arn") or "")
    public_regions = []
    for dist in (dist_config.get("distributions") or []):
        ami = (dist or {}).get("amiDistributionConfiguration") or {}
        groups = [str(g).lower() for g in ((ami.get("launchPermission") or {})
                                           .get("userGroups") or [])]
        if "all" in groups:
            public_regions.append(str(dist.get("region") or "?"))
    return {
        "config": name, "regions": public_regions, "public": bool(public_regions),
        "statement": (
            f"Image Builder distribution configuration {name} grants public launch "
            f"permission in region(s) {', '.join(public_regions)}. Every AMI any pipeline "
            f"using this configuration produces becomes readable by all AWS accounts — "
            f"including builds that do not exist yet and have been reviewed by nobody"
            if public_regions else ""),
    }


def imagebuilder_cleanup_disabled(recipe: Mapping) -> dict:
    """IMGB-03 / 17.2 — an image recipe whose user-data override bypasses build cleanup.

    Image Builder runs a cleanup before finalising an AMI: it removes build logs,
    temporary credentials and the agent's working state. Supplying a ``userDataOverride``
    replaces the boot script that arranges it, so unless the override re-creates the
    sentinel file the cleanup looks for, whatever the build touched is baked into the
    image and copied to every instance launched from it."""
    import base64
    name = str(recipe.get("name") or recipe.get("arn") or "")
    override = ((recipe.get("additionalInstanceConfiguration") or {})
                .get("userDataOverride") or "")
    if not override:
        return {"recipe": name, "override": False, "reenabled": None,
                "cleanup_disabled": False, "statement": ""}
    try:
        decoded = base64.b64decode(str(override), validate=False).decode(
            "utf-8", "replace")
    except Exception:
        decoded = str(override)
    reenabled = "/var/lib/amazon/toe/perform_cleanup" in decoded
    return {
        "recipe": name, "override": True, "reenabled": reenabled,
        "cleanup_disabled": not reenabled, "decoded_len": len(decoded),
        "statement": (
            f"Image Builder recipe {name} sets a userDataOverride that does not re-enable "
            f"the built-in cleanup (it never creates /var/lib/amazon/toe/perform_cleanup). "
            f"Build logs, the component working directory and any temporary credentials "
            f"used during the build are baked into the finished AMI and copied to every "
            f"instance launched from it"
            if not reenabled else ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Declarations
#
# One CheckDef per control, which is where severity, all five compliance keys, the
# remediation command, the detail page and the permission ledger all come from. The
# CIS-COMPUTE key is added per check by `_cis`, so a mapping cannot be forgotten and a
# recommendation number cannot be typed into four places and disagree in one of them.
# ══════════════════════════════════════════════════════════════════════════════
_ACC = {"PCI-DSS": "7.2.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-3"}
_PRIV = {"PCI-DSS": "7.2.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-6"}
_CFG = {"PCI-DSS": "2.2.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.1", "NIST": "CM-6"}
_INV = {"PCI-DSS": "12.5.1", "HIPAA": "164.310(d)(1)", "SOC2": "CC6.1", "NIST": "CM-8"}
_LOG = {"PCI-DSS": "10.2.1", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"}
_MON = {"PCI-DSS": "10.4.1", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "SI-4"}
_NET = {"PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"}
_TLS = {"PCI-DSS": "4.2.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.7", "NIST": "SC-8"}
_CRY = {"PCI-DSS": "3.5.1", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"}
_PAT = {"PCI-DSS": "6.3.3", "HIPAA": "164.308(a)(5)(ii)(B)", "SOC2": "CC7.1", "NIST": "SI-2"}
_INT = {"PCI-DSS": "6.3.2", "HIPAA": "164.312(c)(1)", "SOC2": "CC6.8", "NIST": "SI-7"}


def _cis(base: Mapping, number: str) -> Dict[str, str]:
    """Framework mapping plus this control's Compute-benchmark number.

    Kept as a function rather than written out per check so the CIS-COMPUTE key cannot be
    omitted from one declaration and silently drop that control out of the evidence pack's
    denominator."""
    return dict(base, **{"CIS-COMPUTE": number})


_EC2_READ = (
    _P("ec2:DescribeInstances",
       "read instance state, launch time, monitoring, block-device mappings and attached "
       "security groups -- the whole EC2 hygiene set comes off this one call"),
)

#: Declared in per-service blocks and concatenated at the end. One `register()` call for
#: forty-three checks would be a single expression thousands of lines long, and a syntax
#: error anywhere in it would report at the closing paren.
_COMPUTE_CHECKS = _cd.register(
    # ── Amazon Machine Images ────────────────────────────────────────────────
    _C(id="AMI-04", section="AMI", severity="LOW", compliance=_cis(_INV, "2.1.1"),
       permissions=(
           _P("ec2:DescribeImages",
              "read the names of AMIs this account owns so they can be checked against "
              "the organisation's naming convention"),),
       remediation=(
           "Rename the image by re-registering it under a conforming name and deregistering "
           "the old one, since an AMI name is immutable: aws ec2 copy-image --source-image-id "
           "<AMI_ID> --source-region <REGION> --name <CONFORMING_NAME>, then aws ec2 "
           "deregister-image --image-id <AMI_ID> once nothing references it"),
       risk=(
           "This AMI's name does not match the naming convention configured for this "
           "account. A name is the only thing about an image that a human reads when "
           "deciding whether it is current, what it contains, and whether the launch "
           "template pointing at it should be moved on. When names are inconsistent, "
           "nobody can tell from a list of images which are the golden builds and which "
           "are somebody's forgotten experiment, so stale images are never deregistered "
           "and instances keep launching from whichever one a template happens to name."),
       impact="Images cannot be triaged by name, so stale builds are never retired.",
       steps=(
           "Decide the convention and record it, then set it on the scan so this check "
           "evaluates: OVERWATCH_AMI_NAME_PATTERN or the ami_name_pattern option.",
           "Copy the image under a conforming name: aws ec2 copy-image --source-image-id "
           "<AMI_ID> --source-region <REGION> --name <CONFORMING_NAME>",
           "Re-point launch templates and Auto Scaling groups at the new image id, then "
           "deregister the old one: aws ec2 deregister-image --image-id <AMI_ID>")),

    _C(id="AMI-05", section="AMI", severity="MEDIUM", compliance=_cis(_INT, "2.1.3"),
       permissions=(
           _P("ec2:DescribeInstances",
              "read the AMI id each running instance was launched from"),
           _P("ec2:DescribeImages",
              "resolve the owner of each referenced AMI, which is the only way to tell a "
              "first-party image from a stranger's"),),
       remediation=(
           "Rebuild the instance from an image you own or from an Amazon-owned base: aws ec2 "
           "describe-images --image-ids <AMI_ID> --query 'Images[0].[OwnerId,Name]' to "
           "confirm the origin, then relaunch from an approved image and terminate the "
           "instance. Where the third-party image is genuinely required, add its account to "
           "the trusted-account list so the finding records a decision"),
       risk=(
           "This instance was launched from an AMI owned by an account that is neither this "
           "one, nor an Amazon or AWS Marketplace alias, nor on the trusted-account list. An "
           "AMI is not a package: it is a complete root volume, and whoever published it "
           "chose every binary, every service that starts at boot, every trusted CA in the "
           "store and every account in /etc/passwd. A malicious or merely abandoned public "
           "image gives its publisher a foothold on every instance launched from it, and "
           "nothing in the running instance will ever report where its disk came from."),
       impact="The image publisher chose everything on the root volume, including what "
              "runs at boot.",
       steps=(
           "Establish where the image came from: aws ec2 describe-images --image-ids "
           "<AMI_ID> --query 'Images[0].[OwnerId,ImageOwnerAlias,Name,CreationDate]'",
           "If the origin is not one you can vouch for, rebuild from an image you own and "
           "terminate the instance.",
           "If the third-party image is required, add the owning account to the "
           "trusted-account list so the exception is recorded rather than re-discovered")),

    # ── Organizations tag policy ─────────────────────────────────────────────
    _C(id="EC2-10", section="EC2", severity="LOW", compliance=_cis(_INV, "2.3"),
       permissions=(
           _P("organizations:ListPolicies",
              "determine whether any tag policy exists in the organisation; without one, "
              "tagging is a convention rather than a control"),),
       remediation=(
           "Enable the TAG_POLICY type and create one: aws organizations enable-policy-type "
           "--root-id <ROOT_ID> --policy-type TAG_POLICY, then aws organizations "
           "create-policy --type TAG_POLICY --name org-tags --content file://tag-policy.json "
           "and attach it with aws organizations attach-policy --policy-id <ID> --target-id "
           "<ROOT_OR_OU>"),
       risk=(
           "The organisation has no tag policy, so every tag in every account is whatever "
           "the person who created the resource happened to type. Tag policies are the only "
           "AWS mechanism that makes a tag key mandatory and its values a fixed set; without "
           "one, 'Environment=prod', 'env=Prod' and 'ENV=production' coexist, and every "
           "control that selects resources by tag under-selects silently. That includes "
           "backup plans, cost allocation, and any SCP or IAM policy conditioned on a tag: "
           "each of them quietly skips the resources whose tags do not match, and nothing "
           "reports the misses."),
       impact="Tag-scoped backup, cost and access controls silently skip mistyped resources.",
       steps=(
           "Enable the policy type on the root: aws organizations enable-policy-type "
           "--root-id <ROOT_ID> --policy-type TAG_POLICY",
           "Author the policy with the required keys and their permitted values, then "
           "create it: aws organizations create-policy --type TAG_POLICY --name org-tags "
           "--content file://tag-policy.json",
           "Attach it and check compliance before enforcing: aws organizations attach-policy "
           "--policy-id <ID> --target-id <ROOT_OR_OU>")),

    _C(id="EC2-11", section="EC2", severity="LOW", compliance=_cis(_INV, "2.4"),
       permissions=(
           _P("organizations:ListPolicies",
              "enumerate tag policies so their contents can be read"),
           _P("organizations:DescribePolicy",
              "read each tag policy's content to see which resource types it enforces "
              "tags for -- a policy that governs no ec2: type leaves compute ungoverned"),),
       remediation=(
           "Add ec2 resource types to the tag policy's enforced_for list and update it: aws "
           "organizations update-policy --policy-id <ID> --content file://tag-policy.json, "
           "naming ec2:instance, ec2:volume, ec2:snapshot and ec2:image so the policy covers "
           "the resources that outlive their creator"),
       risk=(
           "Tag policies exist in this organisation but none of them enforces tags for any "
           "ec2: resource type, so compute is outside the one control that makes tagging "
           "mandatory. EC2 is where that costs the most, because its resources outlive the "
           "thing that created them: a volume and its snapshots survive the instance, and "
           "an AMI survives the volume. Without an enforced owner or environment tag on "
           "those, there is nobody to ask whether a four-year-old snapshot of a production "
           "database is still needed, and no way to select it into a deletion or "
           "encryption campaign."),
       impact="EC2 volumes, snapshots and images outlive their creator with no enforced owner.",
       steps=(
           "Read the current policy: aws organizations describe-policy --policy-id <ID> "
           "--query 'Policy.Content'",
           "Add ec2:instance, ec2:volume, ec2:snapshot and ec2:image to the enforced_for "
           "list for each required tag key.",
           "Update it and re-check: aws organizations update-policy --policy-id <ID> "
           "--content file://tag-policy.json")),

    # ── EC2 instance hygiene ─────────────────────────────────────────────────
    _C(id="EC2-12", section="EC2", severity="LOW", compliance=_cis(_PAT, "2.5"),
       permissions=_EC2_READ,
       remediation=(
           "Replace the host rather than patching it further: build a current AMI, move the "
           "launch template to it, and cycle the instance -- aws ec2 describe-instances "
           "--instance-ids <ID> --query 'Reservations[0].Instances[0].[ImageId,LaunchTime]' "
           "to see what it was built from, then terminate it once its replacement is serving"),
       risk=(
           "This instance has been running continuously for longer than the 180-day mark, "
           "which means it has never been rebuilt from a current image. Every change made to "
           "it since launch was made in place: packages installed by hand, configuration "
           "edited during an incident, a debugging tool left behind. None of that is in any "
           "template, so the host cannot be reproduced, and the only record of how it came "
           "to be in its present state is the memory of whoever touched it last. Long-lived "
           "hosts are also where persistence survives, because nothing ever wipes them."),
       impact="The host cannot be reproduced from any template, and nothing ever wipes it.",
       steps=(
           "Confirm what it was built from: aws ec2 describe-instances --instance-ids <ID> "
           "--query 'Reservations[0].Instances[0].[ImageId,LaunchTime]'",
           "Build a current AMI and point the launch template or Auto Scaling group at it.",
           "Cycle the instance and terminate the old one once its replacement is healthy: "
           "aws ec2 terminate-instances --instance-ids <ID>")),

    _C(id="EC2-13", section="EC2", severity="LOW", compliance=_cis(_MON, "2.6"),
       permissions=_EC2_READ,
       remediation=(
           "Turn on detailed monitoring so metrics are published every minute: aws ec2 "
           "monitor-instances --instance-ids <ID>, then confirm with aws ec2 "
           "describe-instances --instance-ids <ID> --query "
           "'Reservations[0].Instances[0].Monitoring'"),
       risk=(
           "This instance publishes CloudWatch metrics at the basic 5-minute interval rather "
           "than the detailed 1-minute one. Every alarm built on those metrics inherits the "
           "resolution: a spike in CPU, network out or disk activity that lasts four minutes "
           "is averaged across a five-minute bucket and may never cross a threshold at all. "
           "Four minutes is long enough to compress and exfiltrate a great deal of data, and "
           "long enough for a cryptominer to be started, observed and stopped. The alarms "
           "still exist and still report healthy, which is worse than having none."),
       impact="Short bursts are averaged away, so alarms report healthy through them.",
       steps=(
           "Enable it: aws ec2 monitor-instances --instance-ids <ID>",
           "For instances launched from a template, set Monitoring.Enabled=true in the "
           "launch template so replacements inherit it.",
           "Confirm: aws ec2 describe-instances --instance-ids <ID> --query "
           "'Reservations[0].Instances[0].Monitoring.State'")),

    _C(id="EC2-14", section="EC2", severity="MEDIUM", compliance=_cis(_NET, "2.7"),
       permissions=_EC2_READ + (
           _P("ec2:DescribeSecurityGroups",
              "identify which group in each VPC is the default one, since 'default' is a "
              "name and the group id differs per VPC"),),
       remediation=(
           "Move the instance to a purpose-built security group and detach the default: aws "
           "ec2 modify-instance-attribute --instance-id <ID> --groups <PURPOSE_BUILT_SG>. "
           "Leave the default group in place but empty -- VPC-04 covers keeping it ruleless"),
       risk=(
           "This instance is attached to its VPC's default security group. The default group "
           "is where every resource that did not choose one ends up, which makes it a shared "
           "container with no owner and no stated purpose: a rule opened for one workload is "
           "inherited by every other member, and nothing in the group records who asked for "
           "it or whether they still need it. Because membership is accidental rather than "
           "designed, the set of things a rule applies to changes over time without anyone "
           "editing the rule, and the group grows monotonically because nobody can safely "
           "remove a rule they cannot attribute."),
       impact="A rule opened for one workload silently applies to every other member.",
       steps=(
           "Create or identify a security group whose purpose is this workload.",
           "Reassign the instance: aws ec2 modify-instance-attribute --instance-id <ID> "
           "--groups <PURPOSE_BUILT_SG>",
           "Confirm the default group has no rules left that anything depends on: aws ec2 "
           "describe-security-groups --group-ids <DEFAULT_SG> --query "
           "'SecurityGroups[0].IpPermissions'")),

    _C(id="EC2-15", section="EC2", severity="LOW", compliance=_cis(_INV, "2.10"),
       permissions=(
           _P("ec2:DescribeNetworkInterfaces",
              "find interfaces in the 'available' state -- detached, still holding an "
              "address and security groups, and attached to nothing that is managed"),),
       remediation=(
           "Delete the detached interface once you have confirmed nothing is waiting to "
           "reattach it: aws ec2 describe-network-interfaces --network-interface-ids <ENI> "
           "to check its description and requester, then aws ec2 delete-network-interface "
           "--network-interface-id <ENI>"),
       risk=(
           "This network interface is in the 'available' state: detached from any instance "
           "yet still holding a private address, a place in its subnet and its security "
           "group memberships. Detached ENIs accumulate because nothing deletes them "
           "automatically, and each one consumes an address from a subnet whose CIDR was "
           "sized for the workload rather than for its debris. They also carry security "
           "group associations forward, so a group that looks in use — and therefore is not "
           "cleaned up — may be referenced only by interfaces attached to nothing."),
       impact="Subnet addresses and security-group references are held by nothing.",
       steps=(
           "Check what created it before deleting: aws ec2 describe-network-interfaces "
           "--network-interface-ids <ENI> --query "
           "'NetworkInterfaces[0].[Description,RequesterId,Status]'",
           "Service-managed interfaces (RDS, Lambda, VPC endpoints) reattach themselves -- "
           "leave those alone.",
           "Delete a genuinely orphaned one: aws ec2 delete-network-interface "
           "--network-interface-id <ENI>")),

    _C(id="EC2-16", section="EC2", severity="LOW", compliance=_cis(_PAT, "2.11"),
       permissions=_EC2_READ,
       remediation=(
           "Snapshot anything worth keeping and terminate the instance: aws ec2 "
           "create-snapshot --volume-id <VOL> --description 'pre-termination <ID>', then aws "
           "ec2 terminate-instances --instance-ids <ID>. If it must stay, tag it with an "
           "owner and a review date so it is a decision rather than an oversight"),
       risk=(
           "This instance has been stopped for longer than 90 days. A stopped instance is "
           "not dormant in the ways that matter: it keeps its EBS volumes and pays for them, "
           "it keeps its IAM instance profile, and it keeps its place in every inventory "
           "that counts hosts. What it does not keep is patches — nothing updates a stopped "
           "instance, and no vulnerability scanner reaches it — so it accrues every "
           "vulnerability published since it stopped and applies all of them at once the "
           "moment somebody starts it, typically without anyone re-reviewing what it is "
           "allowed to reach."),
       impact="It returns to service carrying every vulnerability published while it slept.",
       steps=(
           "Establish whether anything still depends on it, and snapshot what matters: aws "
           "ec2 create-snapshot --volume-id <VOL> --description 'pre-termination <ID>'",
           "Terminate it: aws ec2 terminate-instances --instance-ids <ID>",
           "If it must be retained, tag it with an owner and a review date, and patch it "
           "before it is started")),

    _C(id="EC2-17", section="EC2", severity="LOW", compliance=_cis(_INV, "2.12"),
       permissions=_EC2_READ,
       remediation=(
           "Set the volume to be deleted with its instance: aws ec2 "
           "modify-instance-attribute --instance-id <ID> --block-device-mappings "
           "'[{\"DeviceName\":\"<DEV>\",\"Ebs\":{\"DeleteOnTermination\":true}}]'. Where the "
           "volume genuinely must survive, move its data to a service that has an owner"),
       risk=(
           "An EBS volume attached to this instance is configured to survive its "
           "termination. When the instance goes, the volume stays: still holding whatever "
           "was written to it, attached to nothing, patched by nothing, scanned by nothing, "
           "and named in no inventory that has an owner. This is the ordinary route by which "
           "production data ends up sitting unencrypted in an account years after the "
           "workload that produced it was decommissioned, because the only thing that would "
           "have prompted anyone to look at it — the instance — no longer exists."),
       impact="Data outlives the workload with no owner, no scanning and no review.",
       steps=(
           "Decide whether the volume genuinely needs to outlive the instance. Usually it "
           "does not, and the data belongs somewhere with a lifecycle.",
           "Set the flag: aws ec2 modify-instance-attribute --instance-id <ID> "
           "--block-device-mappings "
           "'[{\"DeviceName\":\"<DEV>\",\"Ebs\":{\"DeleteOnTermination\":true}}]'",
           "Set the same in the launch template so replacement instances inherit it")),

    _C(id="ASG-02", section="EC2", severity="LOW", compliance=_cis(_INV, "2.14"),
       permissions=(
           _P("autoscaling:DescribeAutoScalingGroups",
              "read each group's tags and their PropagateAtLaunch flag -- an untagged "
              "group launches untagged instances continuously"),),
       remediation=(
           "Set PropagateAtLaunch on every tag the group carries: aws autoscaling "
           "create-or-update-tags --tags "
           "ResourceId=<ASG>,ResourceType=auto-scaling-group,Key=Environment,Value=prod,"
           "PropagateAtLaunch=true. Existing instances are not retagged, so tag those "
           "separately with aws ec2 create-tags"),
       risk=(
           "This Auto Scaling group either carries no tags or carries tags that do not "
           "propagate at launch, so every instance it creates arrives untagged. An Auto "
           "Scaling group is not a one-off: it replaces instances on health-check failures, "
           "on scaling events and on every deployment, which means the untagged population "
           "regenerates continuously and cannot be fixed by tagging what is there today. "
           "Everything that selects resources by tag — backup plans, cost allocation, "
           "patch groups, and any policy conditioned on an environment tag — therefore "
           "skips a set of instances that keeps refilling itself."),
       impact="Every replacement instance arrives outside every tag-scoped control.",
       steps=(
           "Add the tags with propagation on: aws autoscaling create-or-update-tags --tags "
           "ResourceId=<ASG>,ResourceType=auto-scaling-group,Key=<K>,Value=<V>,"
           "PropagateAtLaunch=true",
           "Tag the instances that are already running, which propagation does not "
           "retroactively cover: aws ec2 create-tags --resources <IDS> --tags Key=<K>,Value=<V>",
           "Confirm: aws autoscaling describe-auto-scaling-groups "
           "--auto-scaling-group-names <ASG> --query "
           "'AutoScalingGroups[0].Tags[].[Key,PropagateAtLaunch]'")),
)

_ECS_READ = (
    _P("ecs:ListClusters", "enumerate the ECS clusters in this region"),
    _P("ecs:DescribeClusters",
       "read cluster settings and configuration -- Container Insights, ECS Exec session "
       "logging and the Fargate ephemeral-storage key all live here"),
)

_ECS_CHECKS = _cd.register(
    _C(id="ECS-09", section="ECS", severity="MEDIUM", compliance=_cis(_PAT, "3.8"),
       permissions=_ECS_READ + (
           _P("ecs:ListServices", "enumerate the services in each cluster"),
           _P("ecs:DescribeServices",
              "read each service's launch type and pinned Fargate platform version, which "
              "is the only place the runtime version is visible"),),
       remediation=(
           "Move the service to the LATEST platform version so Fargate resumes patching the "
           "runtime beneath it: aws ecs update-service --cluster <CLUSTER> --service "
           "<SERVICE> --platform-version LATEST --force-new-deployment, then confirm with "
           "aws ecs describe-services --cluster <CLUSTER> --services <SERVICE> --query "
           "'services[0].platformVersion'"),
       risk=(
           "This Fargate service is pinned to a platform version below the supported floor. "
           "The Fargate platform is the kernel, the container runtime and the agent that AWS "
           "operates on your behalf, and the only reason it is normally not your problem is "
           "that LATEST is patched continuously without you doing anything. Pinning opts out "
           "of that. Nothing else covers the gap: there is no host to run an agent on, SSM "
           "does not see a Fargate task, and no vulnerability scanner in the account reports "
           "on a Fargate platform version — so a pinned service silently runs an unpatched "
           "runtime for as long as the pin stands, which is usually until someone notices "
           "for an unrelated reason."),
       impact="The task runtime stops receiving patches and nothing in the account reports it.",
       steps=(
           "Confirm the pin: aws ecs describe-services --cluster <CLUSTER> --services "
           "<SERVICE> --query 'services[0].[platformFamily,platformVersion]'",
           "Move to LATEST and redeploy: aws ecs update-service --cluster <CLUSTER> "
           "--service <SERVICE> --platform-version LATEST --force-new-deployment",
           "If the pin exists to work around a platform regression, record which one and a "
           "date to revisit it, so the pin is a decision with an owner")),

    _C(id="ECS-10", section="ECS", severity="LOW", compliance=_cis(_MON, "3.9"),
       permissions=_ECS_READ,
       remediation=(
           "Turn Container Insights on for the cluster: aws ecs update-cluster-settings "
           "--cluster <CLUSTER> --settings name=containerInsights,value=enhanced, and set "
           "the account default so new clusters inherit it: aws ecs put-account-setting "
           "--name containerInsights --value enhanced"),
       risk=(
           "Container Insights is disabled on this cluster, so the only metrics published "
           "are cluster-level counts. Per-task CPU, memory, network and restart counts are "
           "not collected at all, which means a task that is being killed and restarted "
           "continuously is indistinguishable from a healthy one: the desired count is "
           "eventually met either way, and that is the only thing the cluster reports. The "
           "same blindness covers a task consuming far more CPU or network than its "
           "siblings, which is what a compromised container looks like from outside."),
       impact="A crash-looping or resource-abusing task is invisible at the reported level.",
       steps=(
           "Enable it on the cluster: aws ecs update-cluster-settings --cluster <CLUSTER> "
           "--settings name=containerInsights,value=enhanced",
           "Set the account default so new clusters start with it: aws ecs "
           "put-account-setting --name containerInsights --value enhanced",
           "Confirm: aws ecs describe-clusters --clusters <CLUSTER> --include SETTINGS "
           "--query 'clusters[0].settings'")),

    _C(id="ECS-11", section="ECS", severity="LOW", compliance=_cis(_INV, "3.10"),
       permissions=_ECS_READ + (
           _P("ecs:ListServices", "enumerate services so their tags can be read"),
           _P("ecs:DescribeServices", "read service tags, which arrive with the service "
              "description when tags are requested"),),
       remediation=(
           "Tag the service: aws ecs tag-resource --resource-arn <SERVICE_ARN> --tags "
           "key=Owner,value=<TEAM> key=Environment,value=<ENV>, and set the cluster's "
           "propagateTags so tasks inherit them"),
       risk=(
           "This ECS service carries no tags. A service is the long-lived object in ECS — it "
           "is what owns the desired count, the deployment configuration and the load "
           "balancer registration — so it is the natural place for ownership to be recorded, "
           "and when it is absent there is nothing anywhere in the cluster that says which "
           "team runs this workload. Cost allocation attributes its spend to nobody, "
           "tag-conditioned IAM policies do not apply to it, and an incident that starts "
           "with 'who owns this service' starts with a search through deployment history."),
       impact="No owner is recorded anywhere, and tag-scoped policy and cost reporting miss it.",
       steps=(
           "Tag it: aws ecs tag-resource --resource-arn <SERVICE_ARN> --tags "
           "key=Owner,value=<TEAM> key=Environment,value=<ENV>",
           "Set propagateTags on the service so its tasks inherit them: aws ecs "
           "update-service --cluster <CLUSTER> --service <SERVICE> --propagate-tags SERVICE",
           "Confirm: aws ecs describe-services --cluster <CLUSTER> --services <SERVICE> "
           "--include TAGS --query 'services[0].tags'")),

    _C(id="ECS-12", section="ECS", severity="LOW", compliance=_cis(_INV, "3.11"),
       permissions=_ECS_READ,
       remediation=(
           "Tag the cluster: aws ecs tag-resource --resource-arn <CLUSTER_ARN> --tags "
           "key=Owner,value=<TEAM> key=Environment,value=<ENV>, then confirm with aws ecs "
           "describe-clusters --clusters <CLUSTER> --include TAGS"),
       risk=(
           "This ECS cluster carries no tags. The cluster is the boundary that container "
           "instances, services and tasks all sit inside, so it is the coarsest and most "
           "useful place to record which environment this compute belongs to. Without it, "
           "nothing distinguishes a production cluster from a scratch one in any report "
           "built from tags, and any guardrail written as 'deny this action where "
           "Environment=prod' does not apply here — not because someone decided it should "
           "not, but because the condition never matches."),
       impact="Environment-conditioned guardrails do not match, so they do not apply.",
       steps=(
           "Tag it: aws ecs tag-resource --resource-arn <CLUSTER_ARN> --tags "
           "key=Owner,value=<TEAM> key=Environment,value=<ENV>",
           "Check which guardrails were meant to apply to this cluster and confirm the tag "
           "values they test for match exactly.",
           "Confirm: aws ecs describe-clusters --clusters <CLUSTER> --include TAGS --query "
           "'clusters[0].tags'")),

    _C(id="ECS-13", section="ECS", severity="LOW", compliance=_cis(_INV, "3.12"),
       permissions=(
           _P("ecs:ListTaskDefinitions", "enumerate active task-definition revisions"),
           _P("ecs:DescribeTaskDefinition",
              "read the task definition and its tags -- the tags are what say which team "
              "owns the workload the definition describes"),),
       remediation=(
           "Tag the revision: aws ecs tag-resource --resource-arn <TASKDEF_ARN> --tags "
           "key=Owner,value=<TEAM>, and add the tags to the register call so future "
           "revisions carry them: aws ecs register-task-definition --tags "
           "key=Owner,value=<TEAM> --cli-input-json file://taskdef.json"),
       risk=(
           "This task definition carries no tags. Task definitions accumulate faster than "
           "any other ECS object because every deployment registers a new revision, and an "
           "account commonly holds hundreds or thousands of them. Untagged, there is no way "
           "to tell which belong to a live workload and which are the sediment of a service "
           "deleted years ago — so nobody deregisters any of them, and the list stops being "
           "usable for the thing it is needed for, which is finding every definition that "
           "still references a vulnerable image or a role that should have been removed."),
       impact="Stale revisions cannot be told from live ones, so none are ever deregistered.",
       steps=(
           "Tag the current revision: aws ecs tag-resource --resource-arn <TASKDEF_ARN> "
           "--tags key=Owner,value=<TEAM>",
           "Add tags to the registration itself so every future revision carries them: aws "
           "ecs register-task-definition --tags key=Owner,value=<TEAM> --cli-input-json "
           "file://taskdef.json",
           "Deregister revisions nothing references: aws ecs deregister-task-definition "
           "--task-definition <FAMILY>:<REVISION>")),

    _C(id="ECS-14", section="ECS", severity="MEDIUM", compliance=_cis(_INT, "3.13"),
       permissions=(
           _P("ecs:ListTaskDefinitions", "enumerate active task-definition revisions"),
           _P("ecs:DescribeTaskDefinition",
              "read each container definition's image reference, which is the only record "
              "of which registry the running code is pulled from"),),
       remediation=(
           "Mirror the image into an ECR repository in this account and pin it by digest: "
           "aws ecr create-repository --repository-name <REPO>, push the image, then "
           "register a revision whose image is "
           "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/<REPO>@sha256:<DIGEST> using aws ecs "
           "register-task-definition --cli-input-json file://taskdef.json"),
       risk=(
           "This task definition pulls its image from a registry outside this account. What "
           "runs is therefore decided at task start by whoever controls that registry: a "
           "tag can be repointed at different content without the task definition changing "
           "at all, so the deployment that is reviewed and the image that runs are two "
           "different things separated by however long the tag stays put. Mirroring into "
           "ECR moves the decision back inside the account, and pinning by digest makes the "
           "reviewed artefact and the executed artefact the same object rather than the same "
           "name."),
       impact="A tag can be repointed at new content with no change to any reviewed artefact.",
       steps=(
           "Mirror the image into ECR: aws ecr create-repository --repository-name <REPO>, "
           "then docker pull / tag / push against the ECR registry.",
           "Resolve and record the digest: aws ecr describe-images --repository-name <REPO> "
           "--image-ids imageTag=<TAG> --query 'imageDetails[0].imageDigest'",
           "Register a revision pinned by digest rather than by tag, and redeploy the "
           "service onto it")),

    _C(id="ECS-15", section="ECS", severity="HIGH", compliance=_cis(_NET, "3.14"),
       permissions=_ECS_READ + (
           _P("ecs:ListServices", "enumerate services so their task sets can be read"),
           _P("ecs:DescribeTaskSets",
              "read each task set's awsvpc configuration -- a task set carries its own "
              "network configuration, independent of the service's"),),
       remediation=(
           "Recreate the task set with public addressing off and in private subnets: aws ecs "
           "create-task-set --cluster <CLUSTER> --service <SERVICE> --task-definition "
           "<TASKDEF> --network-configuration "
           "'awsvpcConfiguration={subnets=[<PRIVATE_SUBNETS>],securityGroups=[<SG>],"
           "assignPublicIp=DISABLED}', then delete the old one"),
       risk=(
           "This ECS task set assigns public IP addresses to its tasks. Under awsvpc "
           "networking the address lands on the task's own ENI, so every port the container "
           "listens on is reachable from the internet subject only to the security group — "
           "there is no load balancer in front of it deciding what gets through, and no NAT "
           "boundary. What makes a task set the dangerous place for this is that it carries "
           "its own network configuration, separate from the service's: an operator who "
           "corrects the service, verifies it, and closes the ticket has not changed the "
           "task set, and a blue/green or external deployment controller will keep launching "
           "public tasks from it."),
       impact="Container ports are internet-reachable, and fixing the service does not fix it.",
       steps=(
           "List the task sets and their configuration: aws ecs describe-task-sets --cluster "
           "<CLUSTER> --service <SERVICE> --query "
           "'taskSets[].[id,networkConfiguration.awsvpcConfiguration.assignPublicIp]'",
           "Create a replacement with assignPublicIp=DISABLED in private subnets, and put a "
           "load balancer in front if the workload must be reachable.",
           "Delete the public task set once the replacement is serving: aws ecs "
           "delete-task-set --cluster <CLUSTER> --service <SERVICE> --task-set <ID>")),

    _C(id="ECS-16", section="ECS", severity="LOW", compliance=_cis(_NET, "3.15"),
       permissions=(
           _P("ecs:ListTaskDefinitions", "enumerate active task-definition revisions"),
           _P("ecs:DescribeTaskDefinition",
              "read the networkMode, which decides whether tasks get their own ENI or "
              "share the container instance's"),),
       remediation=(
           "Register a revision using awsvpc so each task gets its own ENI and its own "
           "security group: aws ecs register-task-definition --network-mode awsvpc "
           "--cli-input-json file://taskdef.json, then update the service to it with a "
           "networkConfiguration naming the subnets and security groups"),
       risk=(
           "This task definition uses bridge or none networking rather than awsvpc. Under "
           "bridge, every task on a container instance shares that instance's ENI and "
           "therefore its security groups, so the network policy is a property of the host "
           "rather than of the workload: two unrelated tasks scheduled onto the same "
           "instance get identical network access, and a rule opened for one of them is "
           "opened for whatever else lands there later. It also means no flow log, security "
           "group or NACL can distinguish traffic from one task from traffic from another, "
           "because as far as the VPC is concerned there is only the host."),
       impact="Network policy attaches to the host, so unrelated tasks share it.",
       steps=(
           "Register a revision with awsvpc: aws ecs register-task-definition --network-mode "
           "awsvpc --cli-input-json file://taskdef.json",
           "Give the service a networkConfiguration naming its subnets and a security group "
           "scoped to this workload: aws ecs update-service --cluster <CLUSTER> --service "
           "<SERVICE> --task-definition <NEW> --network-configuration "
           "'awsvpcConfiguration={subnets=[<SUBNETS>],securityGroups=[<SG>],"
           "assignPublicIp=DISABLED}'",
           "Check the ENI budget first -- awsvpc consumes one ENI per task, which is capped "
           "per instance type")),

    _C(id="ECS-17", section="ECS", severity="HIGH", compliance=_cis(_LOG, "3.16"),
       permissions=_ECS_READ + (
           _P("ecs:ListServices", "enumerate services to find any with ECS Exec enabled"),
           _P("ecs:DescribeServices",
              "read enableExecuteCommand -- only a cluster where someone can actually open "
              "a session has anything to log"),),
       remediation=(
           "Configure session logging on the cluster: aws ecs update-cluster --cluster "
           "<CLUSTER> --configuration "
           "'executeCommandConfiguration={logging=OVERRIDE,logConfiguration={"
           "cloudWatchLogGroupName=<GROUP>,cloudWatchEncryptionEnabled=true}}', and confirm "
           "with aws ecs describe-clusters --clusters <CLUSTER> --include CONFIGURATIONS"),
       risk=(
           "Services on this cluster have ECS Exec enabled and the cluster does not log the "
           "sessions. ECS Exec is an interactive shell inside a running container: anyone "
           "holding ecs:ExecuteCommand can read the task's environment variables, its "
           "mounted secrets and the credentials its task role is currently holding, and can "
           "run whatever the container's filesystem allows. With logging set to DEFAULT or "
           "NONE, CloudTrail records that a session was opened and nothing about what "
           "happened inside it, so an investigation can establish who connected and to which "
           "task, and nothing at all about what they did once they were there."),
       impact="Interactive shells into production containers leave no record of what was run.",
       steps=(
           "Create or choose a log group for the sessions, and encrypt it.",
           "Set logging to OVERRIDE: aws ecs update-cluster --cluster <CLUSTER> "
           "--configuration 'executeCommandConfiguration={logging=OVERRIDE,"
           "logConfiguration={cloudWatchLogGroupName=<GROUP>,"
           "cloudWatchEncryptionEnabled=true}}'",
           "Review who holds ecs:ExecuteCommand at the same time -- logging a session is "
           "worth much less than not granting it: aws iam simulate-principal-policy "
           "--policy-source-arn <PRINCIPAL> --action-names ecs:ExecuteCommand")),

    _C(id="FARGATE-03", section="ECS", severity="LOW", compliance=_cis(_CRY, "11.1"),
       permissions=_ECS_READ,
       remediation=(
           "Point the cluster's managed storage at a customer-managed key: aws ecs "
           "update-cluster --cluster <CLUSTER> --configuration "
           "'managedStorageConfiguration={fargateEphemeralStorageKmsKeyId=<KEY_ARN>}', "
           "having first granted the Fargate service principal usage of the key in its key "
           "policy"),
       risk=(
           "This cluster encrypts Fargate ephemeral storage with an AWS-owned key. The data "
           "is encrypted either way, so the exposure is not confidentiality at rest — it is "
           "control and evidence. An AWS-owned key has no key policy you can read or narrow, "
           "no grants you can revoke, and produces no CloudTrail entry in your account when "
           "it is used, which means there is no way to demonstrate afterwards who could "
           "decrypt a task's scratch volume, and no way to make it undecryptable quickly if "
           "you need to. Task scratch space routinely holds decrypted secrets, downloaded "
           "artefacts and intermediate copies of whatever the task is processing."),
       impact="No key policy, no revocable grant and no CloudTrail record for task scratch space.",
       steps=(
           "Create or choose a CMK and allow the Fargate service principal to use it in the "
           "key policy.",
           "Point the cluster at it: aws ecs update-cluster --cluster <CLUSTER> "
           "--configuration 'managedStorageConfiguration="
           "{fargateEphemeralStorageKmsKeyId=<KEY_ARN>}'",
           "Confirm: aws ecs describe-clusters --clusters <CLUSTER> --include CONFIGURATIONS "
           "--query "
           "'clusters[0].configuration.managedStorageConfiguration'")),
)

_LMB_READ = (
    _P("lambda:ListFunctions",
       "enumerate the functions in this region together with their configuration -- role, "
       "layers, environment and KMS key all arrive on this one call"),
)

_LAMBDA_CHECKS = _cd.register(
    _C(id="LMB-10", section="LAMBDA", severity="LOW", compliance=_cis(_MON, "12.2"),
       permissions=_LMB_READ,
       remediation=(
           "Attach the CloudWatch Lambda Insights extension layer and grant the execution "
           "role the managed policy it needs: aws lambda update-function-configuration "
           "--function-name <FUNC> --layers "
           "arn:aws:lambda:<REGION>:580247275435:layer:LambdaInsightsExtension:<VERSION>, "
           "then aws iam attach-role-policy --role-name <ROLE> --policy-arn "
           "arn:aws:iam::aws:policy/CloudWatchLambdaInsightsExecutionRolePolicy"),
       risk=(
           "This function has no CloudWatch Lambda Insights extension attached, so the only "
           "telemetry it produces is invocation count, duration, errors and throttles. Those "
           "describe whether the function finished, not what it did. Insights adds "
           "per-invocation CPU, memory, network and init-duration series, which is the only "
           "in-band way to notice that a function's resource profile changed while its code "
           "did not — the signature of a swapped dependency, an injected payload, or a "
           "function being used as a proxy for something it was never meant to reach. "
           "Without it, a function can behave entirely differently and still look identical "
           "in every metric that is being collected."),
       impact="A function whose behaviour changed looks identical in every collected metric.",
       steps=(
           "Attach the layer for your region and architecture: aws lambda "
           "update-function-configuration --function-name <FUNC> --layers "
           "arn:aws:lambda:<REGION>:580247275435:layer:LambdaInsightsExtension:<VERSION>",
           "Grant the execution role the managed policy: aws iam attach-role-policy "
           "--role-name <ROLE> --policy-arn "
           "arn:aws:iam::aws:policy/CloudWatchLambdaInsightsExecutionRolePolicy",
           "Confirm metrics arrive in the /aws/lambda-insights log group before relying on "
           "any alarm built from them")),

    _C(id="LMB-11", section="LAMBDA", severity="MEDIUM", compliance=_cis(_PRIV, "12.5"),
       permissions=_LMB_READ,
       remediation=(
           "Give each function its own role holding only what that function needs: aws iam "
           "create-role --role-name <FUNC>-exec --assume-role-policy-document "
           "file://trust.json, attach a scoped policy, then aws lambda "
           "update-function-configuration --function-name <FUNC> --role <NEW_ROLE_ARN>"),
       risk=(
           "Several functions share one execution role, so the role holds the union of "
           "everything any of them needs and each function runs with all of it. A function "
           "that only reads one queue is therefore holding whatever permissions the "
           "reporting function beside it required, and any code-execution bug in the "
           "smallest of them yields the largest one's access. The second cost is "
           "attributional and shows up during an incident: CloudTrail records the role "
           "session, so a suspicious call can be traced to the role and no further, and "
           "there is no way to tell which of the functions sharing it made the call."),
       impact="Each function runs with the union of every sharer's permissions, "
              "and CloudTrail cannot say which one acted.",
       steps=(
           "List the sharers: aws lambda list-functions --query "
           "'Functions[?Role==`<ROLE_ARN>`].FunctionName'",
           "Create a role per function with only that function's permissions: aws iam "
           "create-role --role-name <FUNC>-exec --assume-role-policy-document file://trust.json",
           "Repoint each function and confirm it still works before deleting the shared "
           "role: aws lambda update-function-configuration --function-name <FUNC> --role "
           "<NEW_ROLE_ARN>")),

    _C(id="LMB-12", section="LAMBDA", severity="MEDIUM", compliance=_cis(_CFG, "12.7"),
       permissions=_LMB_READ + (
           _P("iam:GetRole",
              "establish whether the execution role a function names still exists -- a "
              "deleted role is not visible from the function's own configuration"),),
       remediation=(
           "Point the function at a role that exists, or recreate the one it names: aws iam "
           "create-role --role-name <ROLE> --assume-role-policy-document file://trust.json "
           "with a lambda.amazonaws.com trust, then aws lambda "
           "update-function-configuration --function-name <FUNC> --role <ROLE_ARN>"),
       risk=(
           "This function names an execution role that does not exist. Lambda does not "
           "validate the role continuously, so the function stays deployed and looks healthy "
           "in every listing; it fails at assume-role time, on invocation. That timing is "
           "the problem: the breakage surfaces whenever the next trigger fires, which for a "
           "scheduled job or an error-handling path can be days or weeks after the role was "
           "deleted, and by then the change that caused it is far outside the window anyone "
           "is looking at. Worse, an error-handling or alerting function that fails this way "
           "fails silently at exactly the moment it was needed."),
       impact="The function fails at invocation, long after the change that broke it.",
       steps=(
           "Confirm the role is genuinely gone rather than merely unreadable: aws iam "
           "get-role --role-name <ROLE>",
           "Recreate it with a lambda.amazonaws.com trust and its former permissions, or "
           "point the function at an existing role: aws lambda "
           "update-function-configuration --function-name <FUNC> --role <ROLE_ARN>",
           "Invoke the function once and check the result rather than assuming: aws lambda "
           "invoke --function-name <FUNC> /dev/stdout")),

    _C(id="LMB-13", section="LAMBDA", severity="HIGH", compliance=_cis(_PRIV, "12.9"),
       permissions=_LMB_READ + (
           _P("iam:ListAttachedRolePolicies",
              "enumerate the managed policies on a function's execution role"),
           _P("iam:GetPolicyVersion",
              "read each attached policy's document to find Action '*' on Resource '*', "
              "which is what makes an execution role an administrator"),
           _P("iam:ListRolePolicies",
              "enumerate inline policies, which are where a hand-written wildcard "
              "most often ends up"),
           _P("iam:GetRolePolicy", "read each inline policy document"),),
       remediation=(
           "Replace the wildcard with the actions the function actually calls: aws iam "
           "detach-role-policy --role-name <ROLE> --policy-arn <ADMIN_POLICY>, then attach a "
           "policy built from the function's real usage -- aws iam "
           "generate-service-last-accessed-details --arn <ROLE_ARN> shows which services it "
           "has used"),
       risk=(
           "This function's execution role allows Action '*' on Resource '*'. A Lambda "
           "execution role is not a credential a person holds carefully: it is assumed "
           "automatically on every invocation and its session credentials are available to "
           "the function's own process. That makes it exactly what an attacker obtains from "
           "any code-execution flaw in the handler — a vulnerable dependency, an unsafe "
           "deserialisation, a field of the event that reaches an interpreter — and the "
           "distance from 'this function parses untrusted input' to 'this account has been "
           "taken over' is a single bug, because the role is an administrator."),
       impact="Any code execution inside the handler becomes account-wide administrative access.",
       steps=(
           "Find out what the function has actually used: aws iam "
           "generate-service-last-accessed-details --arn <ROLE_ARN>, then aws iam "
           "get-service-last-accessed-details --job-id <JOB_ID>",
           "Write a policy naming those actions on those resources and attach it.",
           "Remove the wildcard policy: aws iam detach-role-policy --role-name <ROLE> "
           "--policy-arn <ADMIN_POLICY> (or delete-role-policy for an inline one)")),

    _C(id="LMB-14", section="LAMBDA", severity="HIGH", compliance=_cis(_ACC, "12.10"),
       permissions=_LMB_READ + (
           _P("lambda:GetPolicy",
              "read the function's resource policy, which is the only place a grant to "
              "another AWS account is recorded"),),
       remediation=(
           "Remove the grant to the unrecognised account: aws lambda get-policy "
           "--function-name <FUNC> to find the statement id, then aws lambda "
           "remove-permission --function-name <FUNC> --statement-id <SID>. If the access is "
           "genuinely required, add the account to the trusted-account list so it is an "
           "recorded decision"),
       risk=(
           "This function's resource policy grants invoke permission to an AWS account that "
           "is neither this one nor on the trusted-account list. A resource-policy grant is "
           "the quietest kind of cross-account access there is: it does not appear in any "
           "IAM report about this account's principals, it has no expiry, nothing reviews it "
           "on a schedule, and the account it names does not have to do anything for it to "
           "keep working. Grants like this are typically added for a partner or a "
           "cross-account integration and then outlive it by years, at which point the "
           "external account may have changed hands, been sold, or been closed and its id "
           "recycled."),
       impact="An outside account can invoke this function indefinitely, with no review.",
       steps=(
           "Read the policy and identify the statement: aws lambda get-policy "
           "--function-name <FUNC> --query Policy --output text",
           "Establish whether the integration it was added for still exists. Usually it "
           "does not.",
           "Remove it: aws lambda remove-permission --function-name <FUNC> --statement-id "
           "<SID>, or record the account on the trusted list if the access is required")),

    _C(id="LMB-15", section="LAMBDA", severity="MEDIUM", compliance=_cis(_CRY, "12.12"),
       permissions=_LMB_READ,
       remediation=(
           "Encrypt the environment with a customer-managed key: aws kms create-key "
           "--description 'lambda env <FUNC>', then aws lambda "
           "update-function-configuration --function-name <FUNC> --kms-key-arn <KEY_ARN>, "
           "and narrow who may Decrypt in the key policy"),
       risk=(
           "This function's environment variables are encrypted with the AWS-managed Lambda "
           "key rather than a customer-managed one. The values are encrypted at rest either "
           "way, so what this actually decides is who can read them: with the AWS-managed "
           "key, decryption is transparent to any caller, so every principal holding "
           "lambda:GetFunctionConfiguration — a permission commonly granted broadly because "
           "it reads as harmless configuration access — sees the plaintext of every "
           "variable. A customer-managed key moves that decision into a key policy that can "
           "be narrowed to a named set of principals and produces a CloudTrail Decrypt event "
           "each time it is used."),
       impact="Anyone with GetFunctionConfiguration reads the plaintext values.",
       steps=(
           "Create a key for it: aws kms create-key --description 'lambda env <FUNC>'",
           "Point the function at it: aws lambda update-function-configuration "
           "--function-name <FUNC> --kms-key-arn <KEY_ARN>",
           "Narrow the key policy to the execution role and the deployers, and take the "
           "opportunity to move any actual secret out of the environment entirely and into "
           "Secrets Manager")),

    _C(id="LMB-16", section="LAMBDA", severity="HIGH", compliance=_cis(_ACC, "12.13"),
       permissions=(
           _P("lambda:ListLayers", "enumerate the Lambda layers published in this region"),
           _P("lambda:GetLayerVersionPolicy",
              "read a layer version's permission policy, which is the only place a "
              "wildcard principal on published code is recorded"),),
       remediation=(
           "Revoke the public grant: aws lambda get-layer-version-policy --layer-name "
           "<LAYER> --version-number <N> to find the statement id, then aws lambda "
           "remove-layer-version-permission --layer-name <LAYER> --version-number <N> "
           "--statement-id <SID>"),
       risk=(
           "This Lambda layer version is shared with every AWS account. A layer is not a "
           "manifest or a reference — it is a zip of a filesystem that gets unpacked into "
           "/opt in front of the function's own code, so publishing one publicly publishes "
           "whatever was in the build directory when it was created. That is a materially "
           "different exposure from a public S3 object, because nobody re-reads a layer "
           "before shipping it: it is built once by a pipeline, and configuration files, "
           "test fixtures, private packages and occasionally credentials go in with the "
           "dependencies. Revoking the grant later does not un-download anything."),
       impact="Every AWS account can download whatever the build put in the layer.",
       steps=(
           "Read the policy and find the wildcard statement: aws lambda "
           "get-layer-version-policy --layer-name <LAYER> --version-number <N>",
           "Remove it: aws lambda remove-layer-version-permission --layer-name <LAYER> "
           "--version-number <N> --statement-id <SID>",
           "Treat the contents as disclosed: unpack the published layer, look at what was "
           "actually in it, and rotate anything that should not have been")),

    _C(id="LMB-17", section="LAMBDA", severity="MEDIUM", compliance=_cis(_CFG, "12.14"),
       permissions=_LMB_READ + (
           _P("lambda:GetFunctionRecursionConfig",
              "read whether recursive-loop detection is on for a function; the account "
              "default is Terminate, so Allow is always an explicit opt-out"),),
       remediation=(
           "Turn detection back on: aws lambda put-function-recursion-config --function-name "
           "<FUNC> --recursive-loop Terminate, then confirm with aws lambda "
           "get-function-recursion-config --function-name <FUNC>"),
       risk=(
           "Recursive-loop detection is set to Allow on this function, which is an explicit "
           "opt-out from the account default of Terminate. The control exists for a specific "
           "and common failure: a function whose output feeds a trigger that invokes the "
           "same function — writing to the bucket that triggers it, publishing to the topic "
           "it subscribes to — recurses without any bug being visible in the code, because "
           "each individual invocation is correct. With detection off there is nothing to "
           "stop it, and the loop consumes the account's shared concurrency pool, so every "
           "other function in the account is throttled while it runs."),
       impact="A self-triggering loop exhausts the account's shared concurrency pool.",
       steps=(
           "Restore the default: aws lambda put-function-recursion-config --function-name "
           "<FUNC> --recursive-loop Terminate",
           "If Allow is genuinely required by the design, set a reserved concurrency limit "
           "so the loop cannot consume the account pool: aws lambda put-function-concurrency "
           "--function-name <FUNC> --reserved-concurrent-executions <N>",
           "Confirm: aws lambda get-function-recursion-config --function-name <FUNC>")),
)

_LS_BUCKET = (
    _P("lightsail:GetBuckets",
       "read Lightsail bucket access rules, access keys, attached resources and logging "
       "configuration -- all four arrive on this one call"),
)

_SVC_CHECKS = _cd.register(
    # ── Amazon Lightsail ─────────────────────────────────────────────────────
    _C(id="LSAIL-03", section="LIGHTSAIL", severity="LOW", compliance=_cis(_NET, "5.6"),
       permissions=(
           _P("lightsail:GetInstances",
              "read whether an instance has IPv6 networking enabled, which is a separate "
              "address family with a separate firewall rule list"),),
       remediation=(
           "Turn IPv6 off where nothing uses it: aws lightsail disable-add-on "
           "--resource-name <NAME> --add-on-request addOnType=... is not the path -- use aws "
           "lightsail set-ip-address-type --resource-name <NAME> --resource-type Instance "
           "--ip-address-type ipv4, then re-check the firewall with aws lightsail "
           "get-instance-port-states --instance-name <NAME>"),
       risk=(
           "This Lightsail instance has IPv6 networking enabled. The exposure is not IPv6 "
           "itself but how Lightsail presents it: every firewall port entry carries a "
           "separate IPv6 rule list beside its IPv4 one, in a different column of the same "
           "row. An operator restricting SSH to an office range edits the IPv4 side, sees "
           "the port go from open to restricted, and closes the task — while the IPv6 side "
           "of the same entry still says ::/0. The instance is then reachable from the whole "
           "internet on an address that no IPv4 scan of the estate will ever return, and "
           "which most internal tooling does not enumerate at all."),
       impact="Firewall restrictions applied to IPv4 leave the IPv6 rule list wide open.",
       steps=(
           "Check both address families on every port: aws lightsail "
           "get-instance-port-states --instance-name <NAME> --query "
           "'portStates[].[fromPort,protocol,cidrs,ipv6Cidrs]'",
           "If nothing needs IPv6, disable it: aws lightsail set-ip-address-type "
           "--resource-name <NAME> --resource-type Instance --ip-address-type ipv4",
           "If it is needed, mirror every IPv4 restriction into ipv6Cidrs with aws lightsail "
           "put-instance-public-ports")),

    _C(id="LSAIL-04", section="LIGHTSAIL", severity="MEDIUM", compliance=_cis(_ACC, "5.7"),
       permissions=_LS_BUCKET,
       remediation=(
           "Delete the bucket access keys and grant access through IAM or resource "
           "attachment instead: aws lightsail get-bucket-access-keys --bucket-name <BUCKET> "
           "to list them, then aws lightsail delete-bucket-access-key --bucket-name <BUCKET> "
           "--access-key-id <ID> once the consumers have been moved"),
       risk=(
           "This Lightsail bucket is reachable through bucket access keys. A bucket access "
           "key is a static credential with none of the controls an IAM principal has: no "
           "attached policy, so it cannot be scoped to a prefix or a set of actions; no "
           "condition keys, so it cannot be limited by source IP, VPC endpoint or MFA; and "
           "no expiry, so it works until somebody deletes it. Because the key is what "
           "authenticates, CloudTrail records the key id rather than a principal anyone can "
           "look up, so a key that leaks into a repository or a container image is "
           "indistinguishable in the logs from legitimate use."),
       impact="A static, unscopeable, non-expiring credential authenticates as itself.",
       steps=(
           "List what exists: aws lightsail get-bucket-access-keys --bucket-name <BUCKET>",
           "Move consumers to IAM access on the bucket ARN, or attach the Lightsail "
           "instance to the bucket so it uses its own identity: aws lightsail "
           "set-resource-access-for-bucket --resource-name <INSTANCE> --bucket-name "
           "<BUCKET> --access allow",
           "Delete the keys: aws lightsail delete-bucket-access-key --bucket-name <BUCKET> "
           "--access-key-id <ID>")),

    _C(id="LSAIL-05", section="LIGHTSAIL", severity="LOW", compliance=_cis(_ACC, "5.8"),
       permissions=_LS_BUCKET,
       remediation=(
           "Attach the instance that uses the bucket so it authenticates as itself: aws "
           "lightsail set-resource-access-for-bucket --resource-name <INSTANCE> "
           "--bucket-name <BUCKET> --access allow, then confirm with aws lightsail "
           "get-buckets --bucket-name <BUCKET>"),
       risk=(
           "No Lightsail resource is attached to this bucket. Attachment is the mechanism "
           "that lets a Lightsail instance read and write a bucket using its own identity, "
           "the way an instance profile works in EC2. A bucket that is in use with nothing "
           "attached is therefore being reached some other way, and in Lightsail that means "
           "a bucket access key — a static credential sitting in a configuration file or an "
           "environment variable on the instance, where it is copied into every snapshot and "
           "every image made from that instance, and where it survives being handed to "
           "whoever inherits the workload."),
       impact="The bucket is being reached by a static key stored on a host instead.",
       steps=(
           "Confirm the bucket is genuinely in use before changing anything: aws lightsail "
           "get-bucket-metric-data --bucket-name <BUCKET> --metric-name BucketSizeBytes "
           "--period 86400 --start-time <T0> --end-time <T1> --statistics Maximum "
           "--unit Bytes",
           "Attach the instance: aws lightsail set-resource-access-for-bucket "
           "--resource-name <INSTANCE> --bucket-name <BUCKET> --access allow",
           "Remove the access key the instance was using, and delete it from wherever it "
           "was stored on disk")),

    _C(id="LSAIL-06", section="LIGHTSAIL", severity="HIGH", compliance=_cis(_ACC, "5.9"),
       permissions=_LS_BUCKET,
       remediation=(
           "Make the bucket private and stop per-object overrides: aws lightsail "
           "update-bucket --bucket-name <BUCKET> --access-rules "
           "getObject=private,allowPublicOverrides=false, then confirm with aws lightsail "
           "get-buckets --bucket-name <BUCKET> --query 'buckets[0].accessRules'"),
       risk=(
           "This Lightsail bucket is readable anonymously, either because getObject is set "
           "to public or because allowPublicOverrides permits individual objects to be made "
           "public. What makes a Lightsail bucket a worse place for this than S3 is that it "
           "is invisible to the controls people rely on: it does not appear in the S3 "
           "console, S3 Block Public Access does not apply to it, and an audit that "
           "enumerates buckets through the S3 API will not list it at all. So an account "
           "that has correctly locked down every S3 bucket, and can demonstrate it, can "
           "still be serving data anonymously from here with nothing reporting the fact."),
       impact="Anonymous read access that S3 Block Public Access and S3 audits do not cover.",
       steps=(
           "Establish what is in it before changing access, since something may depend on "
           "the public read: aws lightsail get-buckets --bucket-name <BUCKET>",
           "Make it private: aws lightsail update-bucket --bucket-name <BUCKET> "
           "--access-rules getObject=private,allowPublicOverrides=false",
           "If public distribution is genuinely required, put it behind a CDN with an origin "
           "the bucket only trusts, rather than serving anonymously from the bucket")),

    _C(id="LSAIL-07", section="LIGHTSAIL", severity="MEDIUM", compliance=_cis(_LOG, "5.10"),
       permissions=_LS_BUCKET,
       remediation=(
           "Enable access logging into a separate bucket: aws lightsail update-bucket "
           "--bucket-name <BUCKET> --access-log-config "
           "enabled=true,destination=<LOG_BUCKET>,prefix=<BUCKET>/, then confirm with aws "
           "lightsail get-buckets --bucket-name <BUCKET> --query "
           "'buckets[0].accessLogConfig'"),
       risk=(
           "Access logging is disabled on this Lightsail bucket, so there is no record of "
           "which objects were read or by whom. The consequence only becomes visible at the "
           "worst moment: if the bucket is ever found to have been public, or a bucket "
           "access key is found to have leaked, the question is not whether it was exposed "
           "but whether anything was actually taken — and with no logs that question cannot "
           "be answered at all. An organisation that cannot rule out exposure has to assume "
           "it, which turns a misconfiguration that may have harmed nobody into a disclosure "
           "that must be notified."),
       impact="An exposure cannot be shown to have been unexploited, so it must be assumed.",
       steps=(
           "Create or choose a destination bucket that is itself private.",
           "Enable logging: aws lightsail update-bucket --bucket-name <BUCKET> "
           "--access-log-config enabled=true,destination=<LOG_BUCKET>,prefix=<BUCKET>/",
           "Confirm entries are arriving before relying on it: aws lightsail get-buckets "
           "--bucket-name <BUCKET> --query 'buckets[0].accessLogConfig'")),

    # ── AWS App Runner ───────────────────────────────────────────────────────
    _C(id="APRUN-01", section="APPRUNNER", severity="MEDIUM", compliance=_cis(_NET, "6.1"),
       permissions=(
           _P("apprunner:ListServices", "enumerate App Runner services in this region"),
           _P("apprunner:DescribeService",
              "read the service's network configuration -- whether egress goes through a "
              "VPC connector or straight out to the internet"),),
       remediation=(
           "Route the service's egress through your VPC: aws apprunner "
           "create-vpc-connector --vpc-connector-name <NAME> --subnets <SUBNETS> "
           "--security-groups <SG>, then aws apprunner update-service --service-arn <ARN> "
           "--network-configuration "
           "'EgressConfiguration={EgressType=VPC,VpcConnectorArn=<CONNECTOR_ARN>}'"),
       risk=(
           "This App Runner service uses default egress, so everything it initiates — "
           "pulling source or images, reaching its database, calling third-party APIs — "
           "leaves over the public internet from an AWS-managed address outside your "
           "account. Nothing you own is in that path: no security group restricts where it "
           "can connect, no route table constrains it, no VPC endpoint keeps AWS API traffic "
           "off the internet, and no flow log records any of it. That means the service can "
           "reach anything on the internet and you have neither a control to prevent it nor "
           "a record afterwards, which is the property that matters if the code running "
           "there is ever made to fetch or send something it should not."),
       impact="Outbound traffic is unrestricted and unlogged by anything in your account.",
       steps=(
           "Create a VPC connector in the subnets the service should egress from: aws "
           "apprunner create-vpc-connector --vpc-connector-name <NAME> --subnets <SUBNETS> "
           "--security-groups <SG>",
           "Point the service at it: aws apprunner update-service --service-arn <ARN> "
           "--network-configuration 'EgressConfiguration={EgressType=VPC,"
           "VpcConnectorArn=<CONNECTOR_ARN>}'",
           "Add interface VPC endpoints for the AWS services it calls, so that traffic "
           "stays off the internet too")),

    # ── AWS Batch ────────────────────────────────────────────────────────────
    _C(id="BATCH-01", section="BATCH", severity="MEDIUM", compliance=_cis(_LOG, "8.1"),
       permissions=(
           _P("batch:DescribeJobDefinitions",
              "read each job definition's container properties, where the log driver is "
              "configured -- a Batch job runs once and its output is gone with it"),),
       remediation=(
           "Register a revision with an awslogs driver: aws batch register-job-definition "
           "--job-definition-name <NAME> --type container --container-properties "
           "'{\"logConfiguration\":{\"logDriver\":\"awslogs\",\"options\":"
           "{\"awslogs-group\":\"/aws/batch/job\"}}}' merged with the existing properties"),
       risk=(
           "This Batch job definition has a container with no log configuration. A Batch job "
           "is ephemeral by design: the container starts, runs once, and is destroyed, and "
           "with no log driver its stdout and stderr are destroyed with it. Batch is "
           "normally used for exactly the workloads where that hurts most — data processing "
           "and ETL runs that touch large volumes of production data on a schedule, often "
           "unattended — so a job that failed halfway, processed the wrong input, or was "
           "made to do something else leaves behind an exit code and nothing else. There is "
           "no host to log into afterwards, because there is no host."),
       impact="A job's entire output is destroyed with the container that produced it.",
       steps=(
           "Read the current definition: aws batch describe-job-definitions "
           "--job-definition-name <NAME> --status ACTIVE",
           "Register a revision adding logConfiguration with the awslogs driver and a log "
           "group, keeping the rest of the container properties unchanged.",
           "Point the job queue's submissions at the new revision and deregister the old "
           "one: aws batch deregister-job-definition --job-definition <NAME>:<REVISION>")),

    _C(id="BATCH-02", section="BATCH", severity="MEDIUM", compliance=_cis(_ACC, "8.2"),
       permissions=(
           _P("iam:ListRoles", "find roles trusted by the Batch service principal"),
           _P("iam:GetRole",
              "read the trust policy and its conditions -- aws:SourceArn and "
              "aws:SourceAccount are what stop a service role being usable on behalf of "
              "somebody else's Batch request"),),
       remediation=(
           "Add a source condition to the trust policy so the role can only be assumed for "
           "your own Batch resources: aws iam update-assume-role-policy --role-name <ROLE> "
           "--policy-document file://trust.json, with an ArnLike condition on aws:SourceArn "
           "naming the specific compute environment or job queue"),
       risk=(
           "This role is assumable by the Batch service principal with no aws:SourceArn or "
           "aws:SourceAccount condition, or with one whose value is a wildcard. A service "
           "principal is shared: batch.amazonaws.com acts for every Batch customer, not only "
           "for you, so a trust policy that names the service and nothing else says 'any "
           "Batch request may assume me'. This is the confused-deputy shape AWS documents "
           "for every service trust — the service is trusted, is asked to act, and cannot "
           "tell on whose behalf it should be acting. The source condition is what supplies "
           "the missing half, by naming the specific resource in your account that the "
           "assumption must be for."),
       impact="A shared service principal can be induced to use this role for another party.",
       steps=(
           "Read the current trust: aws iam get-role --role-name <ROLE> --query "
           "'Role.AssumeRolePolicyDocument'",
           "Add an ArnLike condition on aws:SourceArn naming the compute environment or job "
           "queue, not a wildcard over the resource type.",
           "Apply and re-check: aws iam update-assume-role-policy --role-name <ROLE> "
           "--policy-document file://trust.json")),

    # ── AWS Elastic Beanstalk ────────────────────────────────────────────────
    _C(id="EB-01", section="BEANSTALK", severity="MEDIUM", compliance=_cis(_PAT, "10.1"),
       permissions=(
           _P("elasticbeanstalk:DescribeEnvironments",
              "enumerate the Beanstalk environments in this region"),
           _P("elasticbeanstalk:DescribeConfigurationSettings",
              "read the environment's configuration options, which is where managed "
              "updates, log streaming, listeners and access logs are all recorded"),),
       remediation=(
           "Turn managed platform updates on with a weekly window: aws elasticbeanstalk "
           "update-environment --environment-name <ENV> --option-settings "
           "Namespace=aws:elasticbeanstalk:managedactions,OptionName=ManagedActionsEnabled,"
           "Value=true Namespace=aws:elasticbeanstalk:managedactions,"
           "OptionName=PreferredStartTime,Value=Sun:03:00 "
           "Namespace=aws:elasticbeanstalk:managedactions:platformupdate,"
           "OptionName=UpdateLevel,Value=minor"),
       risk=(
           "Managed platform updates are disabled on this Beanstalk environment. Beanstalk's "
           "whole proposition is that it owns the layer beneath the application — the AMI, "
           "the language runtime, the web server and the proxy in front of it — and managed "
           "updates are the mechanism by which that layer gets patched. Switched off, the "
           "platform version freezes at whatever it was when the environment was created, "
           "and nothing else covers it: the instances are not in a patch group anybody "
           "manages, no vulnerability scanner in the account reports a Beanstalk platform "
           "version, and the application team reasonably believes the platform is somebody "
           "else's responsibility, which it was until this was turned off."),
       impact="The runtime and proxy freeze at their creation-day version, unpatched and unreported.",
       steps=(
           "Check how far behind it is: aws elasticbeanstalk describe-environments "
           "--environment-names <ENV> --query 'Environments[0].PlatformArn'",
           "Enable managed updates with a maintenance window: aws elasticbeanstalk "
           "update-environment --environment-name <ENV> --option-settings "
           "Namespace=aws:elasticbeanstalk:managedactions,OptionName=ManagedActionsEnabled,"
           "Value=true",
           "Set the update level to minor so patch and minor platform releases apply "
           "without a manual step")),

    _C(id="EB-02", section="BEANSTALK", severity="MEDIUM", compliance=_cis(_LOG, "10.2"),
       permissions=(
           _P("elasticbeanstalk:DescribeEnvironments",
              "enumerate environments so their configuration can be read"),
           _P("elasticbeanstalk:DescribeConfigurationSettings",
              "read whether instance logs are streamed to CloudWatch Logs rather than "
              "left on instances that are replaced continuously"),),
       remediation=(
           "Stream instance logs to CloudWatch Logs with a retention period: aws "
           "elasticbeanstalk update-environment --environment-name <ENV> --option-settings "
           "Namespace=aws:elasticbeanstalk:cloudwatch:logs,OptionName=StreamLogs,Value=true "
           "Namespace=aws:elasticbeanstalk:cloudwatch:logs,OptionName=RetentionInDays,"
           "Value=90"),
       risk=(
           "This Beanstalk environment does not stream instance logs off the host. Beanstalk "
           "replaces instances constantly and by design — on every deployment, on every "
           "scaling event, and whenever a health check decides an instance is unhealthy — "
           "and logs held only on the instance are destroyed with it. The result is "
           "perverse: the logs most likely to be lost are the ones explaining why an "
           "instance was replaced, because the replacement is what deletes them. An "
           "investigation into a crash, an intrusion or a bad deploy therefore arrives to "
           "find that the platform has already tidied away the evidence as part of "
           "recovering."),
       impact="The logs explaining a failure are deleted by the recovery from that failure.",
       steps=(
           "Enable streaming: aws elasticbeanstalk update-environment --environment-name "
           "<ENV> --option-settings Namespace=aws:elasticbeanstalk:cloudwatch:logs,"
           "OptionName=StreamLogs,Value=true",
           "Set a retention period so the group does not keep everything forever: "
           "OptionName=RetentionInDays,Value=90",
           "Confirm the log groups appear and are receiving events: aws logs "
           "describe-log-groups --log-group-name-prefix /aws/elasticbeanstalk/<ENV>")),

    _C(id="EB-03", section="BEANSTALK", severity="MEDIUM", compliance=_cis(_LOG, "10.3"),
       permissions=(
           _P("elasticbeanstalk:DescribeEnvironments",
              "enumerate environments so their load-balancer options can be read"),
           _P("elasticbeanstalk:DescribeConfigurationSettings",
              "read AccessLogsS3Enabled on the environment's load balancer -- the only "
              "per-request record of what reached the application"),),
       remediation=(
           "Turn on load-balancer access logs to S3: aws elasticbeanstalk update-environment "
           "--environment-name <ENV> --option-settings "
           "Namespace=aws:elbv2:loadbalancer,OptionName=AccessLogsS3Enabled,Value=true "
           "Namespace=aws:elbv2:loadbalancer,OptionName=AccessLogsS3Bucket,Value=<BUCKET>"),
       risk=(
           "The load balancer in front of this Beanstalk environment does not write access "
           "logs. The access log is the only per-request record of what reached the "
           "application: which path, from which client address, with what user agent, and "
           "what the application returned. Without it the environment can report how many "
           "requests failed and nothing about which ones, so an investigation into a "
           "suspected injection, a credential-stuffing run or a scraped endpoint has counts "
           "and no requests. Application logs do not substitute, because the requests that "
           "matter most are frequently the ones the application rejected or never handled."),
       impact="No per-request record exists, so an investigation has counts and no requests.",
       steps=(
           "Create an S3 bucket for the logs with a policy allowing the ELB log-delivery "
           "principal to write to it.",
           "Enable it: aws elasticbeanstalk update-environment --environment-name <ENV> "
           "--option-settings Namespace=aws:elbv2:loadbalancer,"
           "OptionName=AccessLogsS3Enabled,Value=true "
           "Namespace=aws:elbv2:loadbalancer,OptionName=AccessLogsS3Bucket,Value=<BUCKET>",
           "Confirm objects are landing in the bucket before relying on them")),

    _C(id="EB-04", section="BEANSTALK", severity="HIGH", compliance=_cis(_TLS, "10.4"),
       permissions=(
           _P("elasticbeanstalk:DescribeEnvironments",
              "enumerate environments so their listeners can be read"),
           _P("elasticbeanstalk:DescribeConfigurationSettings",
              "read the listener protocol per port -- a Beanstalk environment terminates "
              "TLS at its load balancer or nowhere at all"),),
       remediation=(
           "Add an HTTPS listener with an ACM certificate and redirect HTTP to it: aws "
           "elasticbeanstalk update-environment --environment-name <ENV> --option-settings "
           "Namespace=aws:elbv2:listener:443,OptionName=Protocol,Value=HTTPS "
           "Namespace=aws:elbv2:listener:443,OptionName=SSLCertificateArns,Value=<ACM_ARN> "
           "Namespace=aws:elbv2:listener:443,OptionName=ListenerEnabled,Value=true"),
       risk=(
           "This Beanstalk environment's load balancer has no HTTPS listener, so the "
           "application is served over plaintext HTTP. A Beanstalk environment terminates "
           "TLS at the load balancer or not at all, which means every credential, session "
           "cookie, API token and piece of submitted data crosses the public internet "
           "readable by anything on the path. Nothing inside the environment can detect "
           "this: the application sees ordinary requests arriving and has no way to know "
           "they were readable in transit, and the health checks stay green throughout. It "
           "also makes session hijacking trivial on any shared network, because the session "
           "cookie is transmitted in clear on every request."),
       impact="Credentials and session cookies cross the internet in clear text.",
       steps=(
           "Request or import a certificate: aws acm request-certificate --domain-name "
           "<DOMAIN> --validation-method DNS",
           "Add the HTTPS listener: aws elasticbeanstalk update-environment "
           "--environment-name <ENV> --option-settings "
           "Namespace=aws:elbv2:listener:443,OptionName=Protocol,Value=HTTPS "
           "Namespace=aws:elbv2:listener:443,OptionName=SSLCertificateArns,Value=<ACM_ARN>",
           "Redirect port 80 to 443 rather than leaving it serving, and set HSTS in the "
           "application so browsers stop trying plaintext first")),

    # ── EC2 Image Builder ────────────────────────────────────────────────────
    _C(id="IMGB-02", section="IMAGEBUILDER", severity="HIGH", compliance=_cis(_ACC, "17.1"),
       permissions=(
           _P("imagebuilder:ListDistributionConfigurations",
              "enumerate the distribution configurations pipelines use"),
           _P("imagebuilder:GetDistributionConfiguration",
              "read each region's amiDistributionConfiguration launch permissions -- this "
              "is what decides who can launch every AMI the pipeline will ever build"),),
       remediation=(
           "Remove the public launch permission from the distribution configuration: aws "
           "imagebuilder update-distribution-configuration --distribution-configuration-arn "
           "<ARN> --distributions file://distributions.json with launchPermission naming "
           "specific userIds or organizationArns instead of userGroups: [all]"),
       risk=(
           "This Image Builder distribution configuration grants public launch permission, "
           "so every AMI produced by any pipeline that uses it becomes readable by all AWS "
           "accounts. The distinction from a single public AMI matters: a public AMI is one "
           "mistake with a known blast radius, whereas a public distribution configuration "
           "is a standing instruction that applies to builds that do not exist yet and have "
           "been reviewed by nobody. An AMI is a complete root volume, so whatever the next "
           "build bakes in — configuration, agent credentials, a private package, a "
           "developer's key left in the golden image — is published automatically on the "
           "day it is built."),
       impact="Every future build is published automatically, including unreviewed ones.",
       steps=(
           "Read the current configuration: aws imagebuilder get-distribution-configuration "
           "--distribution-configuration-arn <ARN>",
           "Replace userGroups: [all] with explicit userIds or organizationArns, and apply: "
           "aws imagebuilder update-distribution-configuration "
           "--distribution-configuration-arn <ARN> --distributions file://distributions.json",
           "Find AMIs already published by it and revoke their launch permission: aws ec2 "
           "modify-image-attribute --image-id <AMI_ID> --launch-permission "
           "'{\"Remove\":[{\"Group\":\"all\"}]}'")),

    _C(id="IMGB-03", section="IMAGEBUILDER", severity="MEDIUM", compliance=_cis(_INT, "17.2"),
       permissions=(
           _P("imagebuilder:ListImageRecipes",
              "enumerate the image recipes defined in this account"),
           _P("imagebuilder:GetImageRecipe",
              "read additionalInstanceConfiguration.userDataOverride, which replaces the "
              "boot script that arranges the built-in build cleanup"),),
       remediation=(
           "Have the override re-enable the cleanup by creating the sentinel file the "
           "builder looks for, then update the recipe: add 'mkdir -p /var/lib/amazon/toe && "
           "touch /var/lib/amazon/toe/perform_cleanup' to the user data and register a new "
           "recipe version with aws imagebuilder create-image-recipe --cli-input-json "
           "file://recipe.json"),
       risk=(
           "This image recipe sets a userDataOverride that does not re-enable Image "
           "Builder's built-in cleanup. That cleanup is what removes the build's leftovers "
           "before the AMI is finalised: component logs, the task-orchestrator working "
           "directory, and the temporary credentials the build used to fetch components and "
           "artefacts. Supplying user data replaces the boot script that arranges it, and "
           "unless the replacement creates the sentinel file the builder checks for, all of "
           "that is baked into the finished image. Every instance launched from that AMI "
           "then carries a copy, including the build logs — which routinely record the "
           "parameters, URLs and occasionally the secrets the build was given."),
       impact="Build logs, working state and temporary credentials are baked into every AMI.",
       steps=(
           "Decode and read the override to see what it actually does: aws imagebuilder "
           "get-image-recipe --image-recipe-arn <ARN> --query "
           "'imageRecipe.additionalInstanceConfiguration.userDataOverride'",
           "Add 'mkdir -p /var/lib/amazon/toe && touch "
           "/var/lib/amazon/toe/perform_cleanup' to the user data, or implement an "
           "equivalent cleanup of your own before finalisation.",
           "Register the new recipe version and rebuild, then treat images built from the "
           "old recipe as containing build-time material")),
)

#: Every check this module declares, in declaration order. The scanner imports this to
#: prove the module is wired: a CheckDef that no production code path can reach is the
#: exact defect `tests/test_unreached_modules.py` exists to catch.
CHECKS = _COMPUTE_CHECKS + _ECS_CHECKS + _LAMBDA_CHECKS + _SVC_CHECKS
