#!/usr/bin/env python3
"""
cnapp_validate.py — post-onboarding connection validation & health (CNAPP Phase 8).

After a customer deploys the read-only CloudFormation role, the platform must
confirm — WITHOUT touching customer workloads — that the role is (a) assumable by
the hub, (b) pointed at the RIGHT account, and (c) actually granting read access.
This module is the PURE decision engine for that: it runs a fixed 4-step probe
sequence through INJECTED callables (an assume-role fn + a client factory + an
injected epoch clock) so it is fully unit-testable offline with fakes and imports
NO boto3.

Design invariants
-----------------
* **Pure** — stdlib only; every timestamp is caller-supplied (``now_epoch``), so a
  ValidationResult is deterministic and golden-testable.
* **Read-only of customer workloads** — the only calls are ``sts:AssumeRole``,
  ``sts:GetCallerIdentity``, a SecurityAudit-covered describe canary
  (``ec2:DescribeRegions``), and optionally ``organizations:ListAccounts``.
* **Account mismatch is a HARD STOP** — if the assumed role reports a different
  account than the one being onboarded, the verdict is UNAUTHORIZED and no further
  probing happens. This blocks an operator wiring the wrong account's role.
* **Confused-deputy honesty** — the ExternalId is forwarded to the injected
  assume-role fn; a failure names BOTH the trust-principal and the ExternalId as
  candidate causes so the remediation is actionable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, List, Mapping, Optional

from aws_state import make_scan_ts

# Injected dependency contracts (kept boto3-free):
#   assume_role_fn(role_arn, external_id, session_name, region) -> credentials mapping
#   client_factory(credentials|None, service, region)          -> a client object
Credentials = Mapping[str, Any]
AssumeRoleFn = Callable[[str, Optional[str], str, str], Credentials]
ClientFactory = Callable[[Optional[Credentials], str, str], Any]

DEFAULT_CANARY = "ec2:DescribeRegions"     # SecurityAudit-covered, read-only, cheap
DEFAULT_SESSION = "cnapp-onboard-validate"

# Codes that mean "not a verdict yet — retry soon" rather than "denied".
_TRANSIENT = frozenset({
    "Throttling", "ThrottlingException", "RequestThrottled", "RequestLimitExceeded",
    "RequestTimeout", "RequestTimeoutException", "ServiceUnavailable", "InternalError",
    "InternalFailure", "ConnectTimeoutError", "ReadTimeoutError", "EndpointConnectionError",
})
# Codes that mean the role/stack is not there YET (customer hasn't finished deploy).
_PENDING = frozenset({"NoSuchEntity", "ValidationError"})

# Cadence (seconds to next re-check) per health state.
_CADENCE_HEALTHY = 6 * 3600
_CADENCE_DEGRADED = 3600
_CADENCE_VALIDATING = 60
_CADENCE_UNAUTH_BASE = 15 * 60
_CADENCE_MAX = 24 * 3600


class ConnectionHealth(str, Enum):
    VALIDATING = "validating"     # transient / not-yet-deployed — poll again soon
    HEALTHY = "healthy"           # assumable, right account, reads work
    DEGRADED = "degraded"         # assumable + right account, but a read perm is missing
    UNAUTHORIZED = "unauthorized" # cannot assume, or wrong account (hard stop)


# Actionable operator messages by botocore error Code (checked substring/exact).
FAILURE_TAXONOMY = {
    "AccessDenied": (
        "The hub could not assume the role.",
        "Confirm the CloudFormation stack is deployed, the role's trust policy "
        "allows the hub role (arn:aws:iam::<HUB>:role/CnappHubRole), AND the "
        "sts:ExternalId condition matches the value issued at onboarding."),
    "AccessDeniedException": (
        "The hub could not assume the role.",
        "Confirm the trust principal (hub role ARN) and the sts:ExternalId condition."),
    "NoSuchEntity": (
        "The scanner role does not exist yet.",
        "Deploy the CloudFormation stack/StackSet in the target account, then re-validate."),
    "ValidationError": (
        "The role or ExternalId parameter looks malformed.",
        "Re-run onboarding to reissue the CloudFormation parameters."),
    "Throttling": (
        "AWS throttled the validation probe.",
        "Transient — the platform will retry automatically."),
    "AccessDeniedCanary": (
        "The role is assumable but lacks read (describe/list) access.",
        "Attach the SecurityAudit and ViewOnlyAccess managed policies to the role."),
    "AccessDeniedOrg": (
        "The role cannot list organization accounts.",
        "For org-wide onboarding, grant organizations:ListAccounts (or onboard "
        "per-account); single-account scanning is unaffected."),
}


@dataclass
class CheckResult:
    name: str                      # assume_role|caller_identity|security_audit_canary|org_list_accounts
    status: str                    # ok | fail | skip
    detail: str
    error_code: Optional[str] = None
    remediation: Optional[str] = None

    def to_dict(self) -> dict:
        return {"name": self.name, "status": self.status, "detail": self.detail,
                "error_code": self.error_code, "remediation": self.remediation}


@dataclass
class ValidationResult:
    expected_account_id: str
    role_arn: str
    region: str
    org_mode: bool
    observed_account_id: Optional[str] = None
    checks: List[CheckResult] = field(default_factory=list)
    health: ConnectionHealth = ConnectionHealth.VALIDATING
    ok: bool = False
    validated_at_epoch: int = 0
    validated_at_iso: str = ""
    next_revalidation_epoch: int = 0
    org_account_count: Optional[int] = None
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "expected_account_id": self.expected_account_id,
            "observed_account_id": self.observed_account_id,
            "role_arn": self.role_arn, "region": self.region, "org_mode": self.org_mode,
            "health": self.health.value, "ok": self.ok,
            "validated_at_epoch": self.validated_at_epoch,
            "validated_at_iso": self.validated_at_iso,
            "next_revalidation_epoch": self.next_revalidation_epoch,
            "org_account_count": self.org_account_count,
            "summary": self.summary,
            "checks": [c.to_dict() for c in self.checks],
        }


def _error_code(exc: BaseException) -> str:
    """Extract a botocore-style error Code without importing botocore. Falls back
    to the exception class name (mirrors aws_live_scanner's e.response['Error']
    handling)."""
    resp = getattr(exc, "response", None)
    if isinstance(resp, Mapping):
        err = resp.get("Error")
        if isinstance(err, Mapping):
            code = err.get("Code")
            if code:
                return str(code)
    return type(exc).__name__


def _taxonomy(code: str, *, key: Optional[str] = None):
    entry = FAILURE_TAXONOMY.get(key or code)
    if entry is None:
        entry = ("Validation step failed.", f"Investigate the {code} error from AWS.")
    return entry


def cadence(health: ConnectionHealth, consecutive_failures: int = 0) -> int:
    """Seconds until the next scheduled re-validation for a given verdict.
    UNAUTHORIZED backs off exponentially (capped at 24h) so a permanently-broken
    connection is not re-probed every minute forever."""
    if health == ConnectionHealth.HEALTHY:
        return _CADENCE_HEALTHY
    if health == ConnectionHealth.DEGRADED:
        return _CADENCE_DEGRADED
    if health == ConnectionHealth.VALIDATING:
        return _CADENCE_VALIDATING
    # UNAUTHORIZED
    exp = _CADENCE_UNAUTH_BASE * (2 ** min(max(consecutive_failures, 0), 6))
    return min(exp, _CADENCE_MAX)


def validate_connection(*, expected_account_id: str, role: str, now_epoch: int,
                        assume_role_fn: AssumeRoleFn, client_factory: ClientFactory,
                        external_id: Optional[str] = None, region: str = "us-east-1",
                        org_mode: bool = False, canary: str = DEFAULT_CANARY,
                        session_name: str = DEFAULT_SESSION) -> ValidationResult:
    """Run the fixed onboarding validation sequence and return a ValidationResult.

    Steps: (a) sts:AssumeRole -> (b) sts:GetCallerIdentity + account assertion ->
    (c) SecurityAudit canary (ec2:DescribeRegions) -> (d) organizations:ListAccounts
    (org_mode only). Any step after a hard failure is recorded as ``skip``. Pure:
    all AWS access is via the injected ``assume_role_fn`` / ``client_factory``."""
    ts = make_scan_ts(now_epoch)
    res = ValidationResult(expected_account_id=expected_account_id, role_arn=role,
                           region=region, org_mode=org_mode,
                           validated_at_epoch=ts.epoch, validated_at_iso=ts.iso)

    def finish(health: ConnectionHealth, summary: str) -> ValidationResult:
        res.health = health
        res.ok = health == ConnectionHealth.HEALTHY
        res.next_revalidation_epoch = ts.epoch + cadence(health)
        res.summary = summary
        return res

    def skip_rest(after: str):
        order = ["assume_role", "caller_identity", "security_audit_canary"]
        if org_mode:
            order.append("org_list_accounts")
        started = order.index(after) + 1
        for nm in order[started:]:
            res.checks.append(CheckResult(nm, "skip", "not attempted — a prior step failed"))

    # ── (a) assume role ──────────────────────────────────────────────────────
    try:
        creds = assume_role_fn(role, external_id, session_name, region)
        res.checks.append(CheckResult("assume_role", "ok", f"Assumed {role}"))
    except BaseException as e:                       # noqa: BLE001 (deliberate broad catch)
        code = _error_code(e)
        msg, rem = _taxonomy(code)
        res.checks.append(CheckResult("assume_role", "fail", msg, error_code=code,
                                      remediation=rem))
        skip_rest("assume_role")
        if code in _TRANSIENT or code in _PENDING:
            return finish(ConnectionHealth.VALIDATING,
                          "Role not yet assumable — retrying: " + msg)
        return finish(ConnectionHealth.UNAUTHORIZED, msg + " " + rem)

    saw_transient = False
    saw_denied = False

    # ── (b) caller identity + account assertion (hard stop on mismatch) ──────
    try:
        sts = client_factory(creds, "sts", region)
        ident = sts.get_caller_identity()
        observed = str((ident or {}).get("Account", "") or "")
        res.observed_account_id = observed
        if not observed:
            # Identity could not be established — the account assertion (the module's
            # central invariant) cannot run, so fail CLOSED: never let an unverified
            # connection reach HEALTHY / activate.
            res.checks.append(CheckResult(
                "caller_identity", "fail",
                "GetCallerIdentity returned no Account — identity is unverified.",
                error_code="NoCallerAccount",
                remediation="STS did not report an account; do not trust this "
                            "connection until identity can be confirmed."))
            skip_rest("caller_identity")
            return finish(ConnectionHealth.UNAUTHORIZED,
                          "Identity unverified: STS returned no account.")
        if observed != expected_account_id:
            res.checks.append(CheckResult(
                "caller_identity", "fail",
                f"Role belongs to account {observed}, not {expected_account_id}",
                error_code="AccountMismatch",
                remediation="This role is in the wrong account. Deploy the stack in "
                            f"{expected_account_id}, or onboard {observed} instead."))
            skip_rest("caller_identity")
            return finish(ConnectionHealth.UNAUTHORIZED,
                          f"Account mismatch: assumed role reports {observed}.")
        res.checks.append(CheckResult("caller_identity", "ok",
                                      f"Confirmed account {observed}"))
    except BaseException as e:                       # noqa: BLE001
        code = _error_code(e)
        transient = code in _TRANSIENT
        saw_transient |= transient
        saw_denied |= not transient
        res.checks.append(CheckResult("caller_identity", "fail",
                                      "Could not confirm the caller identity.",
                                      error_code=code,
                                      remediation="Transient — will retry." if transient
                                      else "Unexpected; investigate the STS error."))

    # ── (c) SecurityAudit read canary ────────────────────────────────────────
    try:
        ec2 = client_factory(creds, "ec2", region)
        ec2.describe_regions()
        res.checks.append(CheckResult("security_audit_canary", "ok",
                                      f"Read access confirmed via {canary}"))
    except BaseException as e:                       # noqa: BLE001
        code = _error_code(e)
        transient = code in _TRANSIENT
        saw_transient |= transient
        saw_denied |= not transient
        msg, rem = _taxonomy(code, key="AccessDeniedCanary" if not transient else code)
        res.checks.append(CheckResult("security_audit_canary", "fail", msg,
                                      error_code=code, remediation=rem))

    # ── (d) organizations:ListAccounts (org onboarding only) ─────────────────
    if org_mode:
        try:
            org = client_factory(creds, "organizations", region)
            accounts = _collect_org_accounts(org)
            res.org_account_count = len(accounts)
            res.checks.append(CheckResult("org_list_accounts", "ok",
                                          f"Discovered {len(accounts)} organization account(s)"))
        except BaseException as e:                   # noqa: BLE001
            code = _error_code(e)
            transient = code in _TRANSIENT
            saw_transient |= transient
            saw_denied |= not transient
            msg, rem = _taxonomy(code, key="AccessDeniedOrg" if not transient else code)
            res.checks.append(CheckResult("org_list_accounts", "fail", msg,
                                          error_code=code, remediation=rem))

    # ── overall verdict ──────────────────────────────────────────────────────
    if saw_transient:
        return finish(ConnectionHealth.VALIDATING,
                      "A probe was throttled/timed out — re-validating shortly.")
    if saw_denied:
        return finish(ConnectionHealth.DEGRADED,
                      "Role is assumable but a read permission is missing.")
    return finish(ConnectionHealth.HEALTHY, "Connection healthy — read access confirmed.")


def _collect_org_accounts(org_client) -> List[str]:
    """Count ACTIVE org accounts via the injected client. Supports a paginator
    (real boto3) or a plain list_accounts() (a test fake)."""
    ids: List[str] = []
    try:
        pages = org_client.get_paginator("list_accounts").paginate()
    except (AttributeError, TypeError):
        pages = [org_client.list_accounts()]
    for page in pages:
        for a in (page or {}).get("Accounts", []):
            if a.get("Status", "ACTIVE") == "ACTIVE":
                ids.append(a["Id"])
    return ids
