#!/usr/bin/env python3
"""cnapp_secrets.py — the AWS Secrets Manager resolver for the hub's own secrets.

WHAT THIS IS FOR
----------------
Onboarding writes an ExternalId; a connector writes its API token. Neither value
may be persisted in OverWatch's database, so both go to a secret store and only
an opaque ``secretsmanager://`` reference is kept (``cnapp_onboarding``,
``cnapp_connectors.store_secret``). Until now ``build_service()`` wired those
seams to a function that raises, so a real deployment could not onboard an
account or create a connector at all — deliberately loud, but unconfigured.

This is that store, for AWS Secrets Manager.

WHOSE ACCOUNT THIS WRITES TO
----------------------------
The OPERATOR's own, never a scanned customer's. That is why this is a ``cnapp_``
module: the D11 mutation-surface ratchet exempts the hub-local prefix precisely
because these calls touch the operator's own infrastructure. The customer-account
permission ledger (``aws_perm_ledger``) is a different thing entirely and stays
read-only — nothing here belongs in it.

OWNERSHIP IS CHECKED BEFORE ANY OVERWRITE
-----------------------------------------
Rotation re-uses a secret's name, so the write path is create-or-update. An
update is a mutation, and this codebase's actual rule is not "read-only" but
"OverWatch mutates only resources it created". So every secret is TAGGED at
creation, and an update refuses unless the existing secret carries that tag —
the same provenance guard ``aws_sidescan_ebs.is_owned()`` applies to snapshots.
Without it, a name collision with an operator's own secret would silently
overwrite their value.

NO ``ssm://`` PATH
------------------
``_RESOLVABLE_SCHEMES`` admits ``ssm://`` as well, but the secret store has never
been configured in this deployment, so NO refs of any scheme exist yet. Writing
an ssm reader now would be dead code that looks like coverage. An ``ssm://`` ref
raises with a message saying which backend is configured.

IAM FOR THE HUB'S OWN TASK ROLE (not the scanning role)
-------------------------------------------------------
    secretsmanager:CreateSecret      write a new ExternalId / connector token
    secretsmanager:PutSecretValue    rotation
    secretsmanager:GetSecretValue    resolve at scan / delivery time
    secretsmanager:DescribeSecret    the ownership check before an overwrite
    secretsmanager:TagResource       stamp provenance at creation
    kms:Encrypt / kms:Decrypt / kms:GenerateDataKey   only for a customer-managed key

Scope them to the configured prefix, e.g. ``overwatch/*``.

PLAINTEXT NEVER LEAVES THIS MODULE
----------------------------------
No secret value is logged, echoed into an exception, or returned anywhere except
to the caller that asked to resolve it. Error paths name the REFERENCE, never the
value — and never the ref for a schemeless literal, which would BE the secret
(the rule ``cnapp_onboarding.resolve_external_id`` already follows).
"""
from __future__ import annotations

import os
import re
from typing import Callable, Optional

SCHEME = "secretsmanager://"

#: Stamped on every secret this module creates. The update path refuses to write
#: to a secret that does not carry it.
OWNER_TAG_KEY = "cnapp:owner"
OWNER_TAG_VALUE = "overwatch"

#: Secrets Manager permits [A-Za-z0-9/_+=.@-]. The scope ids we are handed are
#: 12-digit account ids and `conn-<hex>` connector ids, but validate rather than
#: trust: a name built from unvalidated input is how one tenant's ref comes to
#: address another's secret.
_SAFE_SCOPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@=+-]{0,180}$")

DEFAULT_PREFIX = "overwatch/"


class SecretStoreError(RuntimeError):
    """Raised for every failure here, so callers never see a raw botocore error
    (whose string can carry request context we would rather not persist)."""


def _validate_scope(scope_id: str) -> str:
    if not scope_id or not _SAFE_SCOPE.match(str(scope_id)):
        raise SecretStoreError(
            "invalid secret scope id: expected an account id or connector id, "
            "got %r" % (scope_id,))
    return str(scope_id)


def secret_name(scope_id: str, *, prefix: str = DEFAULT_PREFIX) -> str:
    return "%s%s" % (prefix, _validate_scope(scope_id))


def ref_for(name: str) -> str:
    return SCHEME + name


def name_from_ref(ref: str) -> str:
    """The secret name inside a ``secretsmanager://`` reference.

    A ref that does not carry the scheme is not resolvable, and is NOT echoed
    back in the error: a schemeless value here would be the raw secret.
    """
    text = str(ref or "")
    if not text.startswith(SCHEME):
        scheme = text.split("://", 1)[0] if "://" in text else "<no-scheme>"
        raise SecretStoreError(
            "this deployment is configured for AWS Secrets Manager and cannot "
            "resolve a %r reference" % (scheme,))
    name = text[len(SCHEME):]
    if not name:
        raise SecretStoreError("empty secret name in reference")
    return name


def _is_ours(client, name: str) -> bool:
    """True when the secret exists AND carries our provenance tag.

    A missing secret is not "not ours" — it is absent, which the caller
    distinguishes. Raising here on AccessDenied is deliberate: an ownership
    check that fails open would let an overwrite through on a permissions error.
    """
    described = client.describe_secret(SecretId=name)
    for tag in described.get("Tags") or []:
        if tag.get("Key") == OWNER_TAG_KEY and tag.get("Value") == OWNER_TAG_VALUE:
            return True
    return False


def make_writer(client_factory: Callable[[], object], *,
                prefix: str = DEFAULT_PREFIX,
                kms_key_id: Optional[str] = None) -> Callable[[str, str], str]:
    """A ``SecretWriter``: ``(scope_id, plaintext) -> "secretsmanager://<name>"``.

    Create-or-update, because rotation re-uses the name. The update branch runs
    only for a secret we created — see the module docstring.
    """
    def write(scope_id: str, plaintext: str) -> str:
        if not plaintext:
            raise SecretStoreError("refusing to store an empty secret")
        name = secret_name(scope_id, prefix=prefix)
        client = client_factory()
        create_kwargs = {
            "Name": name,
            "SecretString": plaintext,
            "Description": "OverWatch-managed secret (never stored in the hub DB)",
            "Tags": [{"Key": OWNER_TAG_KEY, "Value": OWNER_TAG_VALUE}],
        }
        if kms_key_id:
            create_kwargs["KmsKeyId"] = kms_key_id
        try:
            client.create_secret(**create_kwargs)
            return ref_for(name)
        except Exception as exc:                    # noqa: BLE001 - narrowed below
            if type(exc).__name__ not in (
                    "ResourceExistsException", "InvalidRequestException"):
                # Never surface the botocore message: it can echo the request,
                # and the request body is the secret.
                raise SecretStoreError(
                    "could not create secret %r (%s)" % (name, type(exc).__name__))
        # Exists already: rotation, or a name we do not own.
        try:
            owned = _is_ours(client, name)
        except Exception as exc:                    # noqa: BLE001
            raise SecretStoreError(
                "secret %r exists but its ownership could not be verified (%s); "
                "refusing to overwrite" % (name, type(exc).__name__))
        if not owned:
            raise SecretStoreError(
                "secret %r already exists and is not tagged %s=%s, so OverWatch "
                "did not create it. Refusing to overwrite an operator's own "
                "secret; choose a different CNAPP_SECRETS_PREFIX."
                % (name, OWNER_TAG_KEY, OWNER_TAG_VALUE))
        try:
            client.put_secret_value(SecretId=name, SecretString=plaintext)
        except Exception as exc:                    # noqa: BLE001
            raise SecretStoreError(
                "could not rotate secret %r (%s)" % (name, type(exc).__name__))
        return ref_for(name)

    return write


def make_reader(client_factory: Callable[[], object]) -> Callable[[str], str]:
    """A ``SecretReader``: ``"secretsmanager://<name>" -> plaintext``."""
    def read(ref: str) -> str:
        name = name_from_ref(ref)
        client = client_factory()
        try:
            got = client.get_secret_value(SecretId=name)
        except Exception as exc:                    # noqa: BLE001
            raise SecretStoreError(
                "could not resolve secret %r (%s)" % (name, type(exc).__name__))
        value = got.get("SecretString")
        if value is None:
            # A binary secret is not something any caller here can use, and
            # decoding one blindly would hand a caller bytes it will treat as a
            # token.
            raise SecretStoreError(
                "secret %r holds a binary value; OverWatch stores text secrets"
                % (name,))
        return value

    return read


# ── configuration ──────────────────────────────────────────────────────────

def configured_backend(env=None) -> str:
    env = os.environ if env is None else env
    return (env.get("CNAPP_SECRETS_BACKEND") or "").strip().lower()


def is_configured(env=None) -> bool:
    return configured_backend(env) in ("aws-secrets-manager", "secretsmanager", "aws")


def build_from_env(env=None, client_factory: Optional[Callable[[], object]] = None):
    """``(secret_writer, secret_reader)`` for the configured backend.

    Returns ``None`` when no backend is configured, so ``build_service()`` keeps
    its fail-loud placeholders rather than silently acquiring a store.
    """
    env = os.environ if env is None else env
    if not is_configured(env):
        return None
    prefix = env.get("CNAPP_SECRETS_PREFIX") or DEFAULT_PREFIX
    kms_key_id = env.get("CNAPP_SECRETS_KMS_KEY_ID") or None
    region = env.get("CNAPP_SECRETS_REGION") or env.get("AWS_REGION") or None

    if client_factory is None:
        def client_factory():                      # pragma: no cover - needs boto3+creds
            try:
                import boto3
            except ImportError as exc:
                raise SecretStoreError(
                    "CNAPP_SECRETS_BACKEND is set but boto3 is not installed")
            kwargs = {"region_name": region} if region else {}
            return boto3.client("secretsmanager", **kwargs)

    return (make_writer(client_factory, prefix=prefix, kms_key_id=kms_key_id),
            make_reader(client_factory))
