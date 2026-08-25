#!/usr/bin/env python3
"""aws_sagemaker.py — Phase 4 · slice 4.1: SageMaker depth to Security Hub parity.

OverWatch shipped seven SageMaker checks. Four of them correspond to a Security Hub
control (SageMaker.1/2/3/21); three — Studio domain egress, Studio home-EFS custody,
endpoint-config storage custody — are ours and have no Security Hub equivalent. That
left **21 of the 25 published controls** unanswered, across eight resource types the
scanner never opened.

WHY THIS IS ONE MODULE AND NOT TWENTY-ONE CHECKS
------------------------------------------------
Twelve of the twenty-one ask the *same two questions* of five different resource types:

* is the container network-isolated (``EnableNetworkIsolation``), and
* is traffic between containers encrypted (``EnableInterContainerTrafficEncryption``)?

Data-quality, model-bias, model-explainability and model-quality job definitions all
carry a ``NetworkConfig`` with exactly those two fields, and so does a monitoring
schedule — one level deeper, under ``MonitoringScheduleConfig.MonitoringJobDefinition``.
Writing that logic five times is how the two halves drift apart; ``monitoring_posture()``
reads all five, and ``MONITORING_KINDS`` is the table the scanner iterates.

WHAT THE CONTROL LIST SAYS, READ RATHER THAN RECALLED
-----------------------------------------------------
Every field name, default and severity below comes from the published Security Hub
control reference and from botocore 1.40.51's own service model — the version this
project pins, checked because slice 3.3 found the API reference running well ahead of
it. This time every operation the slice needs is present, so nothing is deferred.

Two readings worth stating, because both could have gone the other way:

* **Absent is not disabled — except where AWS says it is.** ``EnableNetworkIsolation``
  and ``EnableInterContainerTrafficEncryption`` are documented as *false when not
  configured*: SageMaker.14 fails a schedule that has the flag "set to false **or not
  configured**". So an absent flag here is a genuine FAIL, not an unknown — the opposite
  of the ruling in 2.2 on ``requireMMDSV2``, and for the opposite reason: there, no
  default was documented. The difference is sourced, not stylistic.
* **SageMaker.15 is conditional and the others are not.** It fails only for job
  definitions with an instance count of 2 or greater, because inter-container traffic
  does not exist on a single instance. Applying it unconditionally would fail every
  single-instance bias job for a risk it cannot have.

Pure functions over dicts. No boto3, no network, no I/O.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

__all__ = [
    "MONITORING_KINDS", "SUPPORTED_NOTEBOOK_PLATFORMS", "PLATFORM_SOURCE_DATE",
    "REPOSITORY_ACCESS_VPC", "monitoring_posture", "model_posture",
    "feature_group_encryption", "inference_experiment_encryption",
    "endpoint_variant_redundancy", "notebook_platform", "missing_tag_keys",
    "describe_monitoring", "describe_model",
]

#: The five resource types whose NetworkConfig carries the same two flags, with the
#: Security Hub control each pair answers. Ordered as the control list numbers them.
#:
#: (label, list_op, list_key, name_field, describe_op, describe_kwarg,
#:  isolation_control, encryption_control, encryption_is_conditional)
MONITORING_KINDS: Tuple[tuple, ...] = (
    ("data quality job definition",
     "list_data_quality_job_definitions", "JobDefinitionSummaries",
     "MonitoringJobDefinitionName",
     "describe_data_quality_job_definition", "JobDefinitionName",
     "SageMaker.11", "SageMaker.9", False),
    ("model explainability job definition",
     "list_model_explainability_job_definitions", "JobDefinitionSummaries",
     "MonitoringJobDefinitionName",
     "describe_model_explainability_job_definition", "JobDefinitionName",
     "SageMaker.20", "SageMaker.10", False),
    ("model bias job definition",
     "list_model_bias_job_definitions", "JobDefinitionSummaries",
     "MonitoringJobDefinitionName",
     "describe_model_bias_job_definition", "JobDefinitionName",
     "SageMaker.12", "SageMaker.15", True),
    ("model quality job definition",
     "list_model_quality_job_definitions", "JobDefinitionSummaries",
     "MonitoringJobDefinitionName",
     "describe_model_quality_job_definition", "JobDefinitionName",
     "SageMaker.25", "SageMaker.13", False),
    ("monitoring schedule",
     "list_monitoring_schedules", "MonitoringScheduleSummaries",
     "MonitoringScheduleName",
     "describe_monitoring_schedule", "MonitoringScheduleName",
     "SageMaker.14", "SageMaker.22", False),
)

#: SageMaker.8's parameter, which the control reference marks "not customizable".
#: Dated because it is a moving target: a platform supported today ages out, and a
#: hardcoded list with no date silently becomes a wrong answer about patch currency.
SUPPORTED_NOTEBOOK_PLATFORMS: Tuple[str, ...] = ("notebook-al2023-v1",)
PLATFORM_SOURCE_DATE = "2026-08-25"

#: RepositoryAccessMode: "Vpc" pulls the image from a private registry reachable in the
#: VPC; "Platform" pulls from the public SageMaker registry. SageMaker.16/19 fail on
#: Platform, and on a container with no ImageConfig at all.
REPOSITORY_ACCESS_VPC = "Vpc"

#: Minimum instance count at which inter-container traffic exists (SageMaker.15).
_MULTI_INSTANCE = 2


def _d(v) -> dict:
    return v if isinstance(v, dict) else {}


def _flag(cfg: dict, key: str) -> bool:
    """Read a NetworkConfig boolean.

    ``bool()`` on an absent key gives False, which is CORRECT here and deliberately so:
    the control reference fails a resource whose flag is "set to false or not
    configured". Elsewhere in this codebase an absent field means *unknown* — this is
    the documented exception, not an oversight."""
    return _d(cfg).get(key) is True


def _network_config(detail: Optional[dict]) -> dict:
    """The NetworkConfig for any of the five kinds.

    A monitoring schedule nests it one level deeper than a job definition, under
    MonitoringScheduleConfig.MonitoringJobDefinition. Handling that here rather than at
    five call sites is the whole reason this function exists."""
    d = _d(detail)
    if "NetworkConfig" in d:
        return _d(d.get("NetworkConfig"))
    inner = _d(_d(d.get("MonitoringScheduleConfig")).get("MonitoringJobDefinition"))
    return _d(inner.get("NetworkConfig"))


#: The resources key differs by kind and the difference is easy to miss: a job
#: definition carries ``JobResources``, a monitoring schedule's inline definition
#: carries ``MonitoringResources``. Reading only the first returns 0 for every
#: schedule, which would silently make SageMaker.22 inapplicable everywhere — a check
#: that never fires reads exactly like a check that always passes.
_RESOURCE_KEYS = ("JobResources", "MonitoringResources")


def _instance_count(detail: Optional[dict]) -> int:
    """Compute instances configured for a monitoring job, 0 when unstated."""
    d = _d(detail)
    for holder in (d, _d(_d(d.get("MonitoringScheduleConfig"))
                         .get("MonitoringJobDefinition"))):
        for key in _RESOURCE_KEYS:
            n = _d(_d(holder.get(key)).get("ClusterConfig")).get("InstanceCount")
            if isinstance(n, int) and n > 0:
                return n
    return 0


def monitoring_posture(detail: Optional[dict]) -> dict:
    """Network isolation and inter-container encryption for any monitoring resource.

    ``encryption_applicable`` is False on a single instance: there is no inter-container
    traffic to encrypt, and SageMaker.15 says so explicitly for bias jobs. Reporting a
    single-instance job as failing an encryption control would be a finding about a risk
    the configuration cannot have."""
    cfg = _network_config(detail)
    n = _instance_count(detail)
    return {
        "isolated": _flag(cfg, "EnableNetworkIsolation"),
        "encrypted": _flag(cfg, "EnableInterContainerTrafficEncryption"),
        "instance_count": n,
        "encryption_applicable": n >= _MULTI_INSTANCE,
        "vpc": bool(_d(cfg.get("VpcConfig")).get("Subnets")),
    }


def describe_monitoring(label: str, name: str, posture: Optional[dict]) -> str:
    """One line for a monitoring resource that failed one of its two controls."""
    p = posture or {}
    bits = []
    if not p.get("isolated"):
        bits.append("its containers can make outbound network calls")
    if p.get("encryption_applicable") and not p.get("encrypted"):
        bits.append(f"traffic between its {p.get('instance_count')} instances is "
                    f"unencrypted")
    if not bits:
        return ""
    return f"{label} '{name}': " + " and ".join(bits)


def model_posture(detail: Optional[dict]) -> dict:
    """SageMaker.5 (network isolation) and .16/.19 (private registry).

    .16 asks about the PRIMARY container and .19 about the additional containers of a
    multi-container inference pipeline. They are separate controls with separate
    remediations, so the two are counted apart rather than collapsed into 'some
    container is public'."""
    d = _d(detail)
    primary = _d(d.get("PrimaryContainer"))
    extra = [c for c in (d.get("Containers") or []) if isinstance(c, dict)]

    def _vpc_registry(c: dict) -> bool:
        mode = _d(c.get("ImageConfig")).get("RepositoryAccessMode")
        return mode == REPOSITORY_ACCESS_VPC

    # A model has EITHER a PrimaryContainer or a Containers pipeline. When only the
    # pipeline is present its first entry is the primary for .16's purposes.
    has_primary = bool(primary)
    primary_ok = _vpc_registry(primary) if has_primary else (
        _vpc_registry(extra[0]) if extra else False)
    pipeline = extra[1:] if (not has_primary and extra) else extra
    public_pipeline = [c.get("ContainerHostname") or c.get("Image") or "container"
                       for c in pipeline if not _vpc_registry(c)]
    return {
        "isolated": d.get("EnableNetworkIsolation") is True,
        "primary_private_registry": primary_ok,
        "has_pipeline": bool(pipeline),
        "public_pipeline_containers": public_pipeline,
        "vpc": bool(_d(d.get("VpcConfig")).get("Subnets")),
    }


def describe_model(name: str, posture: Optional[dict]) -> str:
    p = posture or {}
    bits = []
    if not p.get("isolated"):
        bits.append("network isolation is off, so the container can reach the internet "
                    "and AWS credentials are available to it")
    if not p.get("primary_private_registry"):
        bits.append("its primary container image is pulled from the public platform "
                    "registry rather than a private one in your VPC")
    n = len(p.get("public_pipeline_containers") or [])
    if n:
        bits.append(f"{n} pipeline container(s) also pull from the public registry")
    return f"Model '{name}': " + "; ".join(bits) if bits else ""


def feature_group_encryption(detail: Optional[dict]) -> dict:
    """SageMaker.17 (offline store) and .18 (online store, standard storage only).

    ``online_applicable`` matters: the control names STANDARD storage, and an InMemory
    online store is a different product with different semantics. Failing one for a
    control scoped to the other would be a finding the operator cannot act on."""
    d = _d(detail)
    offline = _d(d.get("OfflineStoreConfig"))
    online = _d(d.get("OnlineStoreConfig"))
    storage = online.get("StorageType")
    return {
        "has_offline": bool(offline),
        "offline_kms": bool(_d(offline.get("S3StorageConfig")).get("KmsKeyId")),
        "has_online": bool(online) or bool(d.get("OnlineStoreConfig")),
        "online_applicable": storage in (None, "Standard"),
        "online_storage_type": storage or "Standard",
        "online_kms": bool(_d(online.get("SecurityConfig")).get("KmsKeyId")),
    }


def inference_experiment_encryption(detail: Optional[dict]) -> dict:
    """SageMaker.23 (instance storage volume) and .24 (captured data).

    .24 applies only where data capture is enabled — with no capture there is no
    captured payload to encrypt, and the control is about the payload."""
    d = _d(detail)
    storage = _d(d.get("DataStorageConfig"))
    return {
        "instance_kms": bool(d.get("KmsKey")),
        "capture_enabled": bool(storage),
        "data_kms": bool(storage.get("KmsKey")),
    }


def endpoint_variant_redundancy(detail: Optional[dict]) -> dict:
    """SageMaker.4 — production variants with an initial instance count greater than 1.

    Scoped to INSTANCE-BASED variants: the control note says so, and a serverless
    variant has no instance count to raise. Counting one as a single-instance failure
    would fail a configuration that cannot express the fix."""
    d = _d(detail)
    single, applicable = [], 0
    for v in (d.get("ProductionVariants") or []):
        if not isinstance(v, dict):
            continue
        if v.get("ServerlessConfig"):
            continue                      # no instance count exists to raise
        applicable += 1
        n = v.get("InitialInstanceCount")
        if isinstance(n, int) and n <= 1:
            single.append(v.get("VariantName") or "variant")
    return {"applicable": applicable, "single_instance": single}


def notebook_platform(detail: Optional[dict]) -> dict:
    """SageMaker.8 — the notebook runs on a platform SageMaker still supports.

    An ABSENT PlatformIdentifier is reported as unknown rather than unsupported. The
    field is optional on older instances, and calling one unsupported on the strength of
    a missing field would assert an end-of-support date nobody published."""
    ident = _d(detail).get("PlatformIdentifier")
    if not isinstance(ident, str) or not ident:
        return {"known": False, "supported": False, "platform": ""}
    return {"known": True, "platform": ident,
            "supported": ident in SUPPORTED_NOTEBOOK_PLATFORMS}


def missing_tag_keys(tags: Optional[Sequence[dict]],
                     required: Optional[Sequence[str]] = None) -> List[str]:
    """SageMaker.6 / .7 — required tag keys, ignoring AWS's own ``aws:`` tags.

    With no ``requiredKeyTags`` configured the control checks only that SOME non-system
    tag key exists, which is AWS's documented default behaviour and what this returns
    when ``required`` is empty. Tag keys are case sensitive per the reference, so they
    are compared exactly."""
    present = {t.get("Key") for t in (tags or [])
               if isinstance(t, dict) and isinstance(t.get("Key"), str)
               and not t["Key"].startswith("aws:")}
    if required:
        return sorted(k for k in required if k not in present)
    return [] if present else ["<any non-system tag>"]


# ─── the parity table ────────────────────────────────────────────────────────
#: Every published Security Hub SageMaker control, the OverWatch check that answers it,
#: and the severity Security Hub assigns it.
#:
#: This table is what turns "parity" from a claim into something a test can fail on. An
#: auditor asking "do you cover SageMaker.14?" gets a yes or a no from here, and
#: ``test_every_published_control_is_answered`` fails the build if a control is added to
#: the list below without a check behind it.
#:
#: Severities are AWS's, not ours, and two of them CORRECT a value OverWatch shipped:
#: SageMaker.2 (custom VPC) and SageMaker.3 (root access) are both High, and both were
#: MEDIUM here. Under-rating a control while claiming parity with the standard that
#: rates it is the kind of quiet disagreement nobody discovers until an audit.
#:
#: control -> (overwatch_check_id, security_hub_severity, what it checks)
SECURITY_HUB_PARITY: Dict[str, Tuple[str, str, str]] = {
    "SageMaker.1":  ("SM-01", "HIGH",   "notebook direct internet access"),
    "SageMaker.2":  ("SM-04", "HIGH",   "notebook launched in a custom VPC"),
    "SageMaker.3":  ("SM-02", "HIGH",   "notebook root access"),
    "SageMaker.4":  ("SM-08", "MEDIUM", "endpoint production variant redundancy"),
    "SageMaker.5":  ("SM-09", "MEDIUM", "model network isolation"),
    "SageMaker.6":  ("SM-27", "LOW",    "app image config tagged"),
    "SageMaker.7":  ("SM-28", "LOW",    "image tagged"),
    "SageMaker.8":  ("SM-12", "MEDIUM", "notebook on a supported platform"),
    "SageMaker.9":  ("SM-14", "MEDIUM", "data quality job inter-container encryption"),
    "SageMaker.10": ("SM-16", "MEDIUM", "explainability job inter-container encryption"),
    "SageMaker.11": ("SM-13", "MEDIUM", "data quality job network isolation"),
    "SageMaker.12": ("SM-17", "MEDIUM", "model bias job network isolation"),
    "SageMaker.13": ("SM-20", "MEDIUM", "model quality job inter-container encryption"),
    "SageMaker.14": ("SM-21", "MEDIUM", "monitoring schedule network isolation"),
    "SageMaker.15": ("SM-18", "MEDIUM", "model bias job inter-container encryption"),
    "SageMaker.16": ("SM-10", "MEDIUM", "model primary container private registry"),
    "SageMaker.17": ("SM-23", "MEDIUM", "feature group offline store KMS"),
    "SageMaker.18": ("SM-24", "MEDIUM", "feature group online store KMS"),
    "SageMaker.19": ("SM-11", "MEDIUM", "model pipeline containers private registry"),
    "SageMaker.20": ("SM-15", "HIGH",   "explainability job network isolation"),
    "SageMaker.21": ("SM-03", "MEDIUM", "notebook storage volume CMK"),
    "SageMaker.22": ("SM-22", "MEDIUM", "monitoring schedule inter-container encryption"),
    "SageMaker.23": ("SM-25", "MEDIUM", "inference experiment instance storage KMS"),
    "SageMaker.24": ("SM-26", "MEDIUM", "inference experiment captured data KMS"),
    "SageMaker.25": ("SM-19", "HIGH",   "model quality job network isolation"),
}

#: Ours, with no Security Hub equivalent. Named so the parity test can tell "we go
#: beyond the standard here" apart from "we have an unmapped check", which are opposite
#: facts that look identical in a coverage count.
OVERWATCH_ORIGINAL: Dict[str, str] = {
    "SM-05": "Studio domain public-internet egress (AppNetworkAccessType)",
    "SM-06": "Studio home-EFS customer-managed key",
    "SM-07": "endpoint-config storage customer-managed key",
}

#: Source for the control list and its severities, dated for the same reason
#: SUPPORTED_NOTEBOOK_PLATFORMS is: AWS adds controls, and an undated snapshot silently
#: becomes a false parity claim.
PARITY_SOURCE = "https://docs.aws.amazon.com/securityhub/latest/userguide/sagemaker-controls.html"
PARITY_SOURCE_DATE = "2026-08-25"
