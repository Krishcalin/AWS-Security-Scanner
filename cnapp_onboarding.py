#!/usr/bin/env python3
"""
cnapp_onboarding.py — onboarding helpers for the hosted CNAPP (Phase 8).

Turns an "add this account" request into the two artifacts the customer needs — a
per-account **ExternalId** (the confused-deputy secret) and a CloudFormation
**Launch-Stack URL** that deploys the read-only ``CnappScannerRole`` — while
keeping the ExternalId out of the registry: onboarding writes the value to a
secret store via an injected ``secret_writer`` and persists ONLY an opaque
``secretsmanager://`` / ``ssm://`` reference. The value is resolved back at scan
time and forwarded to ``sts:AssumeRole``; it never sits next to ``role_arn`` in a
DB dump.

Pure: stdlib only (``secrets`` for entropy, ``urllib.parse`` for URL building).
All I/O (the secret store) is injected, so this is fully offline-testable.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import quote

ROLE_NAME = "CnappScannerRole"

# Injected I/O contracts:
#   id_gen()                          -> a fresh high-entropy ExternalId (server-side!)
#   secret_writer(account_id, value)  -> stores value, returns an opaque ref string
#   secret_reader(ref)                -> resolves a ref back to the value (or raises)
IdGen = Callable[[], str]
SecretWriter = Callable[[str, str], str]
SecretReader = Callable[[str], str]

_RESOLVABLE_SCHEMES = ("secretsmanager://", "ssm://")


@dataclass(frozen=True)
class OnboardingInit:
    """The onboarding response. ``external_id_ref`` is what the registry persists;
    ``cfn_launch_url`` / ``cli`` (which embed the plaintext ExternalId) are returned
    to the operator to deploy the stack and are NEVER logged or stored."""
    account_id: str
    role_name: str
    external_id_ref: str
    cfn_launch_url: str
    cli: str
    external_id: str = ""     # transient — for the caller's response only, do not persist


def default_id_gen() -> str:
    """A 40-char (160-bit) hex ExternalId. Server-generated ALWAYS — a caller-
    supplied ExternalId would let an attacker pre-register a victim account under a
    value they control, defeating the confused-deputy guard."""
    return secrets.token_hex(20)


def build_launch_url(template_url: str, hub_role_arn: str, external_id: str,
                     region: str = "us-east-1", stack_name: str = ROLE_NAME) -> str:
    """A CloudFormation quick-create console URL with the stack name + parameters
    pre-filled, so the operator just reviews and clicks *Create stack*."""
    base = (f"https://console.aws.amazon.com/cloudformation/home"
            f"?region={quote(region, safe='')}#/stacks/quickcreate")
    q = (f"templateURL={quote(template_url, safe='')}"
         f"&stackName={quote(stack_name, safe='')}"
         f"&param_HubRoleArn={quote(hub_role_arn, safe='')}"
         f"&param_ExternalId={quote(external_id, safe='')}")
    return f"{base}?{q}"


def build_cli(template_url: str, hub_role_arn: str, external_id: str,
              region: str = "us-east-1", stack_name: str = ROLE_NAME) -> str:
    """The equivalent AWS CLI ``create-stack`` invocation (CLI-first operators)."""
    return ("aws cloudformation create-stack \\\n"
            f"  --stack-name {stack_name} \\\n"
            f"  --template-url {template_url} \\\n"
            f"  --parameters ParameterKey=HubRoleArn,ParameterValue={hub_role_arn} "
            f"ParameterKey=ExternalId,ParameterValue={external_id} \\\n"
            f"  --capabilities CAPABILITY_NAMED_IAM --region {region}")


def init_onboarding(account_id: str, region: str = "us-east-1", *,
                    id_gen: IdGen = default_id_gen, secret_writer: SecretWriter,
                    hub_role_arn: str, cfn_template_url: str,
                    stack_name: str = ROLE_NAME) -> OnboardingInit:
    """Mint an ExternalId, persist it to the secret store (returning only a ref),
    and produce the Launch-Stack URL + CLI. The service stores
    ``result.external_id_ref`` on the account row and returns the URL to the
    operator — the plaintext ExternalId is never written to the registry."""
    if not (account_id and len(account_id) == 12 and account_id.isdigit()):
        raise ValueError(f"account_id must be a 12-digit AWS account id, got {account_id!r}")
    external_id = id_gen()
    if not external_id:
        raise ValueError("id_gen produced an empty ExternalId")
    ref = secret_writer(account_id, external_id)
    if not ref or not str(ref).startswith(_RESOLVABLE_SCHEMES):
        raise ValueError(
            f"secret_writer must return a resolvable {_RESOLVABLE_SCHEMES} reference, "
            f"got {ref!r}")
    return OnboardingInit(
        account_id=account_id, role_name=stack_name, external_id_ref=ref,
        cfn_launch_url=build_launch_url(cfn_template_url, hub_role_arn, external_id,
                                        region, stack_name),
        cli=build_cli(cfn_template_url, hub_role_arn, external_id, region, stack_name),
        external_id=external_id)


def resolve_external_id(external_id_ref: Optional[str], *, secret_reader: SecretReader,
                        region: str = "us-east-1") -> Optional[str]:
    """Resolve a stored reference back to the live ExternalId at scan time. A
    ``hmac:`` ref is an audit-only digest and CANNOT be resolved (raises); an
    unknown scheme raises rather than risk treating a literal as a value; ``None``
    (a manually-onboarded account with no ExternalId) returns ``None``."""
    if not external_id_ref:
        return None
    ref = str(external_id_ref)
    if ref.startswith("hmac:"):
        raise ValueError("external_id_ref is an audit-only hmac digest and cannot be "
                         "resolved to a usable ExternalId")
    if ref.startswith(_RESOLVABLE_SCHEMES):
        return secret_reader(ref)
    # NEVER echo the ref itself: a schemeless literal here would BE the raw
    # ExternalId, and this message can reach persisted job errors / logs.
    scheme = ref.split("://", 1)[0] if "://" in ref else "<no-scheme>"
    raise ValueError(f"unknown external_id_ref scheme: {scheme!r}")
