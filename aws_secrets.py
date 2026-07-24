#!/usr/bin/env python3
"""aws_secrets.py — Slice 1 · AWS-resident secrets posture (pure, boto3-free).

Detects WHERE secrets live and their config posture — NEVER the secret VALUE
(read-only-of-CONFIG). Metadata-only: SSM `describe_parameters` fields, and a
name-keyword + content-regex scan of config surfaces (reusing the preview-only
`aws_sidescan.scan_text_secrets`). The reader-path (who can read a secret) reuses
`aws_deepplane.role_can_read_store` with SECRET_READ_ACTIONS — no new matcher.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Tuple

# The identity actions that READ a secret's value. Consumed through the existing
# aws_deepplane.role_can_read_store, so the Secret reader edge matches exactly like
# the DSPM datastores. These are MATCH TARGETS only — never called by the scanner.
SECRET_READ_ACTIONS = frozenset({
    "secretsmanager:getsecretvalue", "ssm:getparameter", "ssm:getparameters",
    "ssm:getparametersbypath",
})

# Credential-shaped config-key / env-var names (normalized: lowercase, alnum-only).
_SECRET_NAME_KEYWORDS = frozenset({
    "password", "passwd", "pwd", "secret", "apikey", "token", "privatekey",
    "accesskey", "secretkey", "credential", "clientsecret", "connectionstring",
    "dbpass", "authtoken", "sessiontoken", "encryptionkey",
})
# Suffixes that make a name a REFERENCE to a secret, not the secret itself
# (SECRET_ARN, API_KEY_ID, SECRET_NAME, TOKEN_URI). Checked as a normalized suffix so a
# real credential that merely CONTAINS such a word (PASSWORDLESS_SECRET) is NOT suppressed.
_SECRET_NAME_REF_SUFFIXES = ("arn", "id", "name", "uri", "url", "region", "account", "path")
# Words that contain a keyword substring but are not secrets (exact, normalized).
_SECRET_NAME_DENY_EXACT = frozenset({"passwordless"})


def _norm(s: Optional[str]) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def name_looks_secret(name: Optional[str]) -> bool:
    """True if a config-key / env-var NAME looks like it holds a credential. Suppresses
    only genuine REFERENCES (``*_ARN``/``*_ID``/``*_NAME``/…) and a small exact deny-list,
    so a real credential whose name merely contains a deny substring (``PASSWORDLESS_SECRET``,
    ``SECRETSMANAGER_FALLBACK_PASSWORD``) is still flagged."""
    n = _norm(name)
    if not n or n in _SECRET_NAME_DENY_EXACT:
        return False
    if not any(kw in n for kw in _SECRET_NAME_KEYWORDS):
        return False
    return not n.endswith(_SECRET_NAME_REF_SUFFIXES)


def _to_epoch(v) -> Optional[int]:
    if v is None:
        return None
    if hasattr(v, "timestamp"):                      # datetime
        try:
            return int(v.timestamp())
        except Exception:
            return None
    if isinstance(v, (int, float)):
        return int(v)
    return None


def classify_ssm_parameter(meta: dict, now_epoch: Optional[int] = None) -> dict:
    """Classify one SSM Parameter Store parameter from its `describe_parameters` metadata
    (NEVER its value). Returns ``{plaintext, kms, tier, stale_days, name_secret}``:
      plaintext = Type is String/StringList (value stored in cleartext at rest)
      kms       = 'none' (plaintext) | 'managed' (SecureString on the aws/ssm key) | 'cmk'
      stale_days= age since LastModifiedDate (rotation staleness), or None if unknown."""
    typ = meta.get("Type", "String")
    plaintext = typ in ("String", "StringList")
    key = (meta.get("KeyId") or "").lower()
    if plaintext:
        kms = "none"
    elif not key or key.endswith("alias/aws/ssm") or key == "alias/aws/ssm":
        kms = "managed"
    else:
        kms = "cmk"
    lm = _to_epoch(meta.get("LastModifiedDate"))
    if lm is None:
        stale = None
    else:
        now = now_epoch if now_epoch is not None else int(time.time())
        stale = max(0, (now - lm) // 86400)
    return {"plaintext": plaintext, "kms": kms, "tier": meta.get("Tier", "Standard"),
            "stale_days": stale, "name_secret": name_looks_secret(meta.get("Name"))}


def env_secret_findings(pairs, surface: str) -> List[dict]:
    """Hardcoded-credential env vars: a NAME that looks like a secret carrying a non-empty
    LITERAL value. ``pairs`` is a list of ``(name, value)``. Callers must pass ONLY the
    plaintext ``environment`` block, NEVER the ``secrets``/``valueFrom`` reference block
    (which is the CORRECT Secrets-Manager/SSM pattern) — else this false-positives on it."""
    out = []
    for name, value in pairs or []:
        if value and str(value).strip() and name_looks_secret(name):
            out.append({"surface": surface, "name": name, "kind": "hardcoded-env"})
    return out


def content_secret_findings(blob, surface: str, entropy_min: float = 4.0) -> List[dict]:
    """Content-regex scan of a config blob (user-data, a template body) for embedded
    secret-shaped tokens. Preview-only (first4…last4), reusing aws_sidescan."""
    import aws_sidescan
    return [{"surface": surface, "kind": f.kind, "preview": f.match_preview, "line": f.line}
            for f in aws_sidescan.scan_text_secrets(blob, source=surface, entropy_min=entropy_min)]


def cfn_plaintext_secret_params(parameters: dict) -> List[str]:
    """CloudFormation template parameters that LOOK like a secret but are declared WITHOUT
    NoEcho, so their values are shown in plaintext in the console/describe-stacks. ``parameters``
    is the template's ``Parameters`` map ({name: {Type, NoEcho, ...}})."""
    out = []
    for pname, spec in (parameters or {}).items():
        if not isinstance(spec, dict):
            continue
        no_echo = str(spec.get("NoEcho", "false")).lower() in ("true", "1", "yes")
        if name_looks_secret(pname) and not no_echo:
            out.append(pname)
    return out
