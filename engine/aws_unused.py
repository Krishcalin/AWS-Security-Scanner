#!/usr/bin/env python3
"""
aws_unused.py — Unused-access / right-sizing signal (CNAPP Phase 5C, CIEM).

Answers "is this powerful principal actually *used*?" and turns the answer into
two things:

  1. A LOW/INFO **right-sizing finding** ("review candidate, not auto-delete")
     listing the services/actions granted-but-unused.
  2. A bounded **exploit-likelihood down-rank** for any attack path that pivots
     through a dormant principal — a dormant admin role stays high-*impact* (so
     it is never suppressed below the reporting threshold) but its path is scored
     as less likely to be actively abused.

Signal sourcing (priority): IAM Access Analyzer *unused-access* (per-action, when
enabled) > Service-Last-Accessed Details / SLAD (always available) > credential
report (users, corroboration). Absence of the analyzer is NEVER read as
"all used" — it degrades to SLAD with an INFO note.

The scoring/emission helpers (:func:`classify_dormancy`, :func:`dormancy_factor`,
:func:`right_sizing_finding`, :func:`downrank_overlay`) are **pure** and unit
tested; only :func:`unused_signal_for` touches AWS (via injected clients, so it
too is testable with mocks).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

DORMANT_AGE_DAYS = 90     # AWS UnusedIAMRole default; overridden by analyzer config
STALE_AGE_DAYS = 45
_DAY = 86400

# Down-rank multipliers (exploit-likelihood only; impact/criticality untouched).
FACTOR_ACTIVE = 1.0
FACTOR_STALE = 0.8
FACTOR_DORMANT = 0.6
FACTOR_FLOOR = 0.5


@dataclass
class UnusedSignal:
    arn: str
    source: str = "NONE"                 # AA | SLAD | CREDREPORT | NONE
    dormant: Optional[bool] = None       # True/False/None(unknown)
    last_used_epoch: Optional[int] = None
    last_used_iso: Optional[str] = None
    granted_services: Optional[int] = None
    used_services: Optional[int] = None
    unused_services: List[str] = field(default_factory=list)
    unused_actions: List[str] = field(default_factory=list)
    window_days: int = DORMANT_AGE_DAYS
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "arn": self.arn, "source": self.source, "dormant": self.dormant,
            "last_used_epoch": self.last_used_epoch, "last_used_iso": self.last_used_iso,
            "granted_services": self.granted_services, "used_services": self.used_services,
            "unused_services": self.unused_services, "unused_actions": self.unused_actions,
            "window_days": self.window_days, "error": self.error,
            "unused_services_json": json.dumps(self.unused_services),
            "unused_actions_json": json.dumps(self.unused_actions),
            "slad_job_status": None,
        }


# ── pure classification / scoring ────────────────────────────────────────────
def classify_dormancy(last_used_epoch: Optional[int], now_epoch: int,
                      create_epoch: Optional[int], window_days: int = DORMANT_AGE_DAYS
                      ) -> Optional[bool]:
    """Decide dormancy from last-used and creation timestamps.

    * last_used present and older than ``window_days``  -> dormant (True)
    * last_used present and recent                       -> not dormant (False)
    * never used (last_used None) AND principal older than the window -> dormant
    * never used but younger than the window -> UNKNOWN (None) — too new to judge
    """
    if last_used_epoch is not None:
        return (now_epoch - last_used_epoch) >= window_days * _DAY
    if create_epoch is not None and (now_epoch - create_epoch) >= window_days * _DAY:
        return True
    return None


def dormancy_factor(sig: UnusedSignal, now_epoch: int,
                    stale_days: int = STALE_AGE_DAYS,
                    dormant_days: int = DORMANT_AGE_DAYS) -> float:
    """Bounded exploit-likelihood multiplier for a principal's paths. Never below
    :data:`FACTOR_FLOOR`; ``None`` dormancy (unknown) => 1.0 (no down-rank =>
    prior behavior)."""
    if sig.dormant is None:
        return FACTOR_ACTIVE
    if sig.dormant:
        return max(FACTOR_FLOOR, FACTOR_DORMANT)
    if sig.last_used_epoch is None:
        return FACTOR_ACTIVE
    age_days = (now_epoch - sig.last_used_epoch) / _DAY
    if age_days >= stale_days:
        return FACTOR_STALE
    return FACTOR_ACTIVE


def right_sizing_finding(sig: UnusedSignal) -> Optional[Dict]:
    """Build a LOW right-sizing finding dict for a dormant/over-permissioned
    principal, or ``None`` if there is nothing to report (active, or unknown with
    no unused surface)."""
    if sig.dormant is None and not sig.unused_services and not sig.unused_actions:
        return None
    if sig.dormant is False and not sig.unused_services and not sig.unused_actions:
        return None
    bits = []
    if sig.dormant:
        last = sig.last_used_iso or "never within window"
        bits.append(f"dormant (last used: {last}, window {sig.window_days}d)")
    if sig.unused_services:
        shown = ", ".join(sig.unused_services[:6])
        more = f" +{len(sig.unused_services) - 6} more" if len(sig.unused_services) > 6 else ""
        bits.append(f"unused services: {shown}{more}")
    if sig.unused_actions:
        bits.append(f"{len(sig.unused_actions)} unused action(s)")
    detail = "; ".join(bits) if bits else "granted permissions appear unused"
    return {
        "check_id": "CIEM-01",
        "severity": "LOW",
        "resource": sig.arn,
        "message": (f"Right-sizing candidate — {detail}. Source: {sig.source}. "
                    f"Review before removal (not auto-deleted) | {sig.arn}"),
        "source": sig.source,
    }


def downrank_overlay(paths: List, factor_by_arn: Dict[str, float]) -> List[Dict]:
    """Pure, non-mutating overlay: for each ranked path, if it traverses a dormant
    principal, report an adjusted exploit-likelihood-weighted score. The most
    dormant hop (lowest factor) applies once — factors are not stacked. Returns a
    list aligned to ``paths`` of ``{index, original_score, adjusted_score,
    factor, dormant_nodes}`` (only for paths actually affected)."""
    out = []
    for i, p in enumerate(paths):
        nodes = getattr(p, "nodes", ()) or ()
        hits = [(n, factor_by_arn[n]) for n in nodes if n in factor_by_arn
                and factor_by_arn[n] < 1.0]
        if not hits:
            continue
        factor = min(f for _n, f in hits)
        original = getattr(p, "score", 0)
        out.append({
            "index": i,
            "original_score": original,
            "adjusted_score": int(round(original * factor)),
            "factor": factor,
            "dormant_nodes": [n for n, _f in hits],
        })
    return out


# ── AWS collection (injected clients; graceful degradation) ──────────────────
def _iso(epoch: Optional[int]) -> Optional[str]:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _to_epoch(dt) -> Optional[int]:
    """Coerce a boto3 datetime (or ISO string) to a UTC epoch int, or None."""
    if dt is None:
        return None
    if isinstance(dt, (int, float)):
        return int(dt)
    try:
        return int(dt.timestamp())
    except Exception:
        try:
            return int(datetime.fromisoformat(str(dt).replace("Z", "+00:00")).timestamp())
        except Exception:
            return None


def find_unused_access_analyzer(accessanalyzer) -> Optional[str]:
    """Return the ARN of an ACCOUNT/ORGANIZATION unused-access analyzer, or None.
    None means the analyzer is not enabled — the caller must degrade to SLAD and
    must NEVER treat this as 'all access used'."""
    if accessanalyzer is None:
        return None
    for atype in ("ACCOUNT_UNUSED_ACCESS", "ORGANIZATION_UNUSED_ACCESS"):
        try:
            resp = accessanalyzer.list_analyzers(type=atype)
            for a in resp.get("analyzers", []):
                if str(a.get("type", "")).endswith("_UNUSED_ACCESS"):
                    return a.get("arn")
        except Exception:
            continue
    return None


def _signal_from_analyzer(arn, accessanalyzer, analyzer_arn, now_epoch,
                          window_days) -> Optional[UnusedSignal]:
    """Read UnusedIAMRole / UnusedPermission findings for ``arn`` from an unused
    access analyzer. Returns a signal, or None if the analyzer had nothing (so
    the caller falls back to SLAD rather than asserting 'all used')."""
    try:
        findings = []
        paginator = None
        try:
            paginator = accessanalyzer.get_paginator("list_findings_v2")
        except Exception:
            paginator = None
        flt = {"resource": {"eq": [arn]}, "status": {"eq": ["ACTIVE"]}}
        if paginator is not None:
            for page in paginator.paginate(analyzerArn=analyzer_arn, filter=flt):
                findings += page.get("findings", [])
        else:
            findings += accessanalyzer.list_findings_v2(
                analyzerArn=analyzer_arn, filter=flt).get("findings", [])
    except Exception as e:
        return UnusedSignal(arn=arn, source="AA", error=str(e), window_days=window_days)

    if not findings:
        return None

    dormant = False
    last_used_epoch = None
    unused_services: List[str] = []
    unused_actions: List[str] = []
    for f in findings:
        ftype = f.get("findingType", "")
        fid = f.get("id")
        detail = {}
        try:
            detail = accessanalyzer.get_finding_v2(
                analyzerArn=analyzer_arn, id=fid) if fid else {}
        except Exception:
            detail = {}
        if ftype == "UnusedIAMRole":
            dormant = True
            for d in detail.get("findingDetails", []):
                rd = d.get("unusedIamRoleDetails") or {}
                last_used_epoch = _to_epoch(rd.get("lastAccessed")) or last_used_epoch
        elif ftype in ("UnusedPermission", "UnusedIAMUserAccessKey",
                       "UnusedIAMUserPassword"):
            for d in detail.get("findingDetails", []):
                pd = d.get("unusedPermissionDetails") or {}
                svc = pd.get("serviceNamespace")
                if svc:
                    unused_services.append(svc)
                for act in pd.get("actions", []):
                    a = act.get("action")
                    if a:
                        unused_actions.append(a)
    return UnusedSignal(
        arn=arn, source="AA", dormant=dormant,
        last_used_epoch=last_used_epoch, last_used_iso=_iso(last_used_epoch),
        unused_services=sorted(set(unused_services)),
        unused_actions=sorted(set(unused_actions)), window_days=window_days)


def _signal_from_slad(arn, iam, now_epoch, window_days, create_epoch=None,
                      sleep: Callable[[float], None] = time.sleep,
                      max_wait: float = 60.0) -> UnusedSignal:
    """Service-Last-Accessed fallback (always available). Spawns the async job,
    polls with bounded exponential backoff, and derives dormancy from the most
    recent LastAuthenticated across services."""
    try:
        job_id = iam.generate_service_last_accessed_details(
            Arn=arn, Granularity="SERVICE_LEVEL")["JobId"]
    except Exception as e:
        return UnusedSignal(arn=arn, source="SLAD", error=str(e), window_days=window_days)

    waited, delay = 0.0, 0.5
    resp = {}
    while waited < max_wait:
        try:
            resp = iam.get_service_last_accessed_details(JobId=job_id)
        except Exception as e:
            return UnusedSignal(arn=arn, source="SLAD", error=str(e), window_days=window_days)
        status = resp.get("JobStatus", "IN_PROGRESS")
        if status != "IN_PROGRESS":
            if status == "FAILED":
                err = resp.get("Error", {})
                return UnusedSignal(arn=arn, source="SLAD",
                                    error=str(err.get("Message") or err.get("Code") or "FAILED"),
                                    window_days=window_days)
            break
        sleep(delay)
        waited += delay
        delay = min(delay * 2, 5.0)

    # Job never completed within the budget -> UNKNOWN, not "used-nothing/dormant".
    # (Parsing an empty ServicesLastAccessed here would misclassify an old, still-
    # running job as dormant=True and wrongly down-rank its paths.)
    if resp.get("JobStatus", "IN_PROGRESS") == "IN_PROGRESS":
        return UnusedSignal(arn=arn, source="SLAD",
                            error="SLAD job did not complete within max_wait",
                            window_days=window_days)

    services = resp.get("ServicesLastAccessed", [])
    # paginate remaining pages if truncated
    marker = resp.get("Marker")
    guard = 0
    while resp.get("IsTruncated") and marker and guard < 50:
        guard += 1
        try:
            resp = iam.get_service_last_accessed_details(JobId=job_id, Marker=marker)
        except Exception:
            break
        services += resp.get("ServicesLastAccessed", [])
        marker = resp.get("Marker")

    granted = len(services)
    used_epochs = [_to_epoch(s.get("LastAuthenticated")) for s in services]
    used_epochs = [e for e in used_epochs if e is not None]
    used = len(used_epochs)
    unused_services = sorted({s.get("ServiceNamespace", "")
                              for s in services
                              if _to_epoch(s.get("LastAuthenticated")) is None
                              and s.get("ServiceNamespace")})
    last_used_epoch = max(used_epochs) if used_epochs else None
    dormant = classify_dormancy(last_used_epoch, now_epoch, create_epoch, window_days)
    return UnusedSignal(
        arn=arn, source="SLAD", dormant=dormant,
        last_used_epoch=last_used_epoch, last_used_iso=_iso(last_used_epoch),
        granted_services=granted, used_services=used,
        unused_services=unused_services, window_days=window_days)


def unused_signal_for(arn: str, iam, accessanalyzer, now_epoch: int,
                      dormant_age_days: int = DORMANT_AGE_DAYS,
                      analyzer_arn: Optional[str] = None,
                      create_epoch: Optional[int] = None,
                      sleep: Callable[[float], None] = time.sleep) -> UnusedSignal:
    """Resolve the best available unused-access signal for a principal ARN.
    Access Analyzer (if a finding exists) > SLAD (always). Never hard-fails:
    every path returns a UnusedSignal (``dormant=None`` when unknown => no
    down-rank => prior behavior)."""
    if analyzer_arn is None:
        analyzer_arn = find_unused_access_analyzer(accessanalyzer)
    if analyzer_arn:
        sig = _signal_from_analyzer(arn, accessanalyzer, analyzer_arn, now_epoch,
                                    dormant_age_days)
        if sig is not None:
            return sig  # analyzer had an active finding for this principal
    return _signal_from_slad(arn, iam, now_epoch, dormant_age_days,
                             create_epoch=create_epoch, sleep=sleep)
