#!/usr/bin/env python3
"""aws_leastpriv.py — Slice 1 · CIEM least-privilege policy generation (pure, boto3-free).

Given a principal's GRANTED actions (from GetAccountAuthorizationDetails) and the
services/actions it ACTUALLY USED (from IAM service-last-accessed, SLAD), emit a
right-sized IAM policy document that drops never-used services and narrows wildcard
actions to the used set. Deterministic + offline-testable; NEVER auto-applied.

Honesty rules baked in:
  * SLAD is a TRACKING WINDOW — "not accessed in the window" is not proof the grant is
    unneeded, so the output is a RECOMMENDATION with the window stated.
  * Empty usage must NEVER become a deny-all policy (recommended=False instead).
  * Service-level narrowing is reliable; action-level narrowing only where the service
    reports TrackedActionsLastAccessed (a small supported set) — otherwise the wildcard
    is kept rather than guessed.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple


def service_of(action: Optional[str]) -> str:
    a = (action or "").strip().lower()
    if a == "*":
        return "*"
    return a.split(":", 1)[0]


def granted_services(statements: List[dict]) -> Set[str]:
    out: Set[str] = set()
    for st in statements or []:
        if st.get("effect") != "Allow":
            continue
        for a in st.get("actions", ()) or ():
            svc = service_of(a)
            if svc != "*":
                out.add(svc)
    return out


def _to_epoch(v) -> Optional[int]:
    if v is None:
        return None
    if hasattr(v, "timestamp"):
        try:
            return int(v.timestamp())
        except Exception:
            return None
    if isinstance(v, (int, float)):
        return int(v)
    return None


def parse_slad_usage(services_last_accessed, now_epoch: int, window_days: int = 90) -> Set[str]:
    """Service namespaces authenticated within the window, from GetServiceLastAccessedDetails
    ``ServicesLastAccessed`` ([{ServiceNamespace, LastAuthenticated}])."""
    cutoff = now_epoch - window_days * 86400
    used: Set[str] = set()
    for s in services_last_accessed or []:
        la = _to_epoch(s.get("LastAuthenticated"))
        if la is not None and la >= cutoff:
            ns = (s.get("ServiceNamespace") or "").lower()
            if ns:
                used.add(ns)
    return used


def parse_action_usage(services_last_accessed, now_epoch: int,
                       window_days: int = 90) -> Dict[str, Set[str]]:
    """Action-level usage ({service: {'svc:action', ...}}) from ACTION_LEVEL SLAD's
    ``TrackedActionsLastAccessed`` — present only for the services IAM tracks at action
    granularity; empty for the rest (then the wildcard is kept, not guessed)."""
    cutoff = now_epoch - window_days * 86400
    out: Dict[str, Set[str]] = {}
    for s in services_last_accessed or []:
        svc = (s.get("ServiceNamespace") or "").lower()
        for a in s.get("TrackedActionsLastAccessed", []) or []:
            la = _to_epoch(a.get("LastAccessedTime"))
            name = (a.get("ActionName") or "").lower()
            if svc and name and la is not None and la >= cutoff:
                out.setdefault(svc, set()).add(f"{svc}:{name}")
    return out


def rightsize_policy(statements: List[dict], used_services: Set[str],
                     used_actions: Optional[Dict[str, Set[str]]] = None,
                     sid_prefix: str = "LeastPriv") -> Tuple[dict, dict]:
    """Return ``(policy_document, delta)``. Drops Allow actions whose SERVICE was never
    used; narrows a ``svc:*`` (or ``*``) wildcard to the used action set where action-level
    usage is known, else keeps it. Only Allow statements contribute (a least-privilege
    grant is allow-only). Resources are preserved verbatim."""
    from fnmatch import fnmatchcase
    used = {s.lower() for s in (used_services or set())}
    uacts = {k.lower(): {x.lower() for x in v} for k, v in (used_actions or {}).items()}
    # Actions explicitly Denied in the source. The generated (allow-only) policy MUST NOT
    # re-grant any of these — an explicit Deny wins in AWS, so including a denied action when
    # narrowing a wildcard would make the recommendation BROADER than the source's effective
    # grant (the opposite of least-privilege). Exclude any action a Deny pattern covers.
    denied: Set[str] = set()
    for st in statements or []:
        if st.get("effect") == "Deny":
            for a in st.get("actions", ()) or ():
                denied.add((a or "").lower())

    def _is_denied(action: str) -> bool:
        return any(action == dp or fnmatchcase(action, dp) for dp in denied)

    kept: List[dict] = []
    removed: Set[str] = set()
    narrowed: Set[str] = set()
    granted: Set[str] = set()
    admin_narrowed = False

    for st in statements or []:
        if st.get("effect") != "Allow":
            continue
        resources = sorted(st.get("resources", set()) or {"*"})
        new_actions: Set[str] = set()
        for action in st.get("actions", ()) or ():
            a = (action or "").lower()
            svc = service_of(a)
            if svc == "*":                                   # all-services admin grant
                admin_narrowed = True
                for us in used:
                    new_actions |= uacts.get(us) or {f"{us}:*"}
                continue
            granted.add(svc)
            if svc not in used:
                removed.add(svc)
                continue
            if a.endswith(":*"):                             # service wildcard on a used service
                if uacts.get(svc):
                    new_actions |= uacts[svc]
                    narrowed.add(svc)
                else:
                    new_actions.add(a)
            else:
                new_actions.add(a)                           # keep a specific granted action
        new_actions = {a for a in new_actions if not _is_denied(a)}   # drop exact-denied
        if new_actions:
            kept.append({"Sid": f"{sid_prefix}{len(kept)}", "Effect": "Allow",
                         "Action": sorted(new_actions), "Resource": resources})

    # Preserve the source's Deny statements VERBATIM so a narrowed wildcard (svc:*) can never
    # re-grant an explicitly denied action — an exact-action filter alone can't catch that, so
    # the Denies must ride along. The generated policy then stays no broader than the source.
    n_allow = len(kept)
    for i, st in enumerate(statements or []):
        if st.get("effect") == "Deny":
            acts = sorted((a or "").lower() for a in st.get("actions", ()) or ())
            if acts:
                kept.append({"Sid": f"{sid_prefix}Deny{i}", "Effect": "Deny",
                             "Action": acts,
                             "Resource": sorted(st.get("resources", set()) or {"*"})})

    reduction = round(100.0 * len(removed) / len(granted), 1) if granted else 0.0
    delta = {"removed_services": sorted(removed), "narrowed_services": sorted(narrowed),
             "kept_services": sorted(granted - removed), "granted_services": sorted(granted),
             "admin_narrowed": admin_narrowed,
             "admin_narrowed_to": sorted(used) if admin_narrowed else [],
             "surface_reduction_pct": reduction}
    return {"Version": "2012-10-17", "Statement": kept}, delta


def recommendation(statements: List[dict], used_services: Set[str],
                   used_actions: Optional[Dict[str, Set[str]]] = None,
                   window_days: int = 90, slad_complete: bool = True) -> dict:
    """Wrap rightsize_policy with the honesty guards. Returns a dict with ``recommended``
    (bool) and, when recommended, ``policy`` + ``delta`` + ``window_days`` + a ``note``.
    Empty usage or an incomplete SLAD job → ``recommended=False`` (never a deny-all)."""
    used = {s.lower() for s in (used_services or set())}
    if not slad_complete:
        return {"recommended": False, "window_days": window_days,
                "reason": "service-last-accessed job did not complete — cannot right-size"}
    if not used:
        return {"recommended": False, "window_days": window_days,
                "reason": ("no service usage in the window — cannot safely right-size "
                           "(empty usage would deny all; widen the window or verify the job)")}
    policy, delta = rightsize_policy(statements, used, used_actions)
    changed = bool(delta["removed_services"] or delta["narrowed_services"]
                   or delta["admin_narrowed"])
    return {"recommended": changed, "policy": policy, "delta": delta,
            "window_days": window_days, "auto_apply": False,
            "note": (f"Generated from IAM service-last-accessed over {window_days} days. "
                     f"'Not accessed in the window' is NOT proof a grant is unneeded — review "
                     f"before applying; never auto-applied.")}
